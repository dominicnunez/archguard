package guard

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type sqlTableReference struct {
	Table string
	Line  int
}

type sqlStatement struct {
	Text string
	Line int
}

func CheckRepository(cfg Config, repoDir string, pkgs []LoadedPackage) ([]Violation, error) {
	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		return nil, err
	}
	sqlViolations, err := CheckSQLFiles(cfg, repoDir)
	if err != nil {
		return nil, err
	}
	violations = append(violations, sqlViolations...)
	sortViolations(violations)
	return dedupeViolations(violations), nil
}

func CheckSQLFiles(cfg Config, repoDir string) ([]Violation, error) {
	if len(cfg.Analysis.SQLTableReferences) == 0 {
		return nil, nil
	}

	var violations []Violation
	for _, rule := range cfg.Analysis.SQLTableReferences {
		files, err := sqlFilesForRule(repoDir, rule)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			data, err := os.ReadFile(filepath.Join(repoDir, filepath.FromSlash(file)))
			if err != nil {
				return nil, fmt.Errorf("read SQL file %s: %w", file, err)
			}
			violations = append(violations, sqlFileRuleViolations(cfg, rule, file, string(data))...)
		}
	}

	sortViolations(violations)
	return dedupeViolations(violations), nil
}

func sqlFilesForRule(repoDir string, rule SQLTableReferenceConfig) ([]string, error) {
	var files []string
	err := filepath.WalkDir(repoDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != repoDir && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(repoDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !sqlFileRulePathMatches(rule, rel) {
			return nil
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk SQL files: %w", err)
	}
	sort.Strings(files)
	return files, nil
}

func sqlFileRulePathMatches(rule SQLTableReferenceConfig, relPath string) bool {
	for _, pattern := range rule.IgnorePaths {
		if wildcardMatch(filepath.ToSlash(pattern), relPath) {
			return false
		}
	}
	for _, pattern := range sqlTableReferencePaths(rule) {
		if wildcardMatch(filepath.ToSlash(pattern), relPath) {
			return true
		}
	}
	return false
}

func sqlTableReferencePaths(rule SQLTableReferenceConfig) []string {
	paths := make([]string, 0, 1+len(rule.Paths))
	if rule.Path != "" {
		paths = append(paths, rule.Path)
	}
	paths = append(paths, rule.Paths...)
	return paths
}

func sqlFileRuleViolations(cfg Config, rule SQLTableReferenceConfig, relPath string, sql string) []Violation {
	info := packageInfo{RelPath: relPath, Internal: true}
	if ignored(cfg, info) {
		return nil
	}

	var violations []Violation
	seen := make(map[sqlTableSeenKey]struct{})
	for _, ref := range sqlTableReferences(sql) {
		owner := tableOwnerModule(cfg, ref.Table)
		if owner == "" {
			continue
		}
		if tableOwnerTargetConfigured(rule.Allow) && !tableOwnerTargetMatches(rule.Allow, owner) {
			violations = append(violations, sqlFileTableViolation(rule, relPath, ref, owner, seen, "SQL file references a table owner outside the configured allowlist")...)
		}
		if tableOwnerTargetConfigured(rule.Disallow) && tableOwnerTargetMatches(rule.Disallow, owner) {
			violations = append(violations, sqlFileTableViolation(rule, relPath, ref, owner, seen, "SQL file references a table owner from the configured denylist")...)
		}
	}

	if rule.MaxOwnersPerStatement > 0 {
		violations = append(violations, sqlFileStatementOwnerViolations(cfg, rule, relPath, sql)...)
	}
	return violations
}

func sqlFileTableViolation(rule SQLTableReferenceConfig, relPath string, ref sqlTableReference, owner string, seen map[sqlTableSeenKey]struct{}, message string) []Violation {
	key := sqlTableSeenKey{file: relPath, table: ref.Table}
	if _, ok := seen[key]; ok {
		return nil
	}
	seen[key] = struct{}{}
	return []Violation{{
		Rule:    ruleSQLCrossModuleTable,
		From:    sqlFilePosition(relPath, ref.Line),
		To:      ref.Table + " (" + owner + ")",
		Message: fmt.Sprintf("%s by analysis policy %q", message, rule.Name),
	}}
}

func sqlFileStatementOwnerViolations(cfg Config, rule SQLTableReferenceConfig, relPath string, sql string) []Violation {
	var violations []Violation
	for _, statement := range sqlStatements(sql) {
		owners := make(map[string]map[string]struct{})
		firstLine := 0
		for _, ref := range sqlTableReferences(statement.Text) {
			owner := tableOwnerModule(cfg, ref.Table)
			if owner == "" {
				continue
			}
			if owners[owner] == nil {
				owners[owner] = make(map[string]struct{})
			}
			owners[owner][ref.Table] = struct{}{}
			if firstLine == 0 {
				firstLine = statement.Line + ref.Line - 1
			}
		}
		if len(owners) <= rule.MaxOwnersPerStatement {
			continue
		}
		violations = append(violations, Violation{
			Rule:    ruleSQLCrossModuleTable,
			From:    sqlFilePosition(relPath, firstLine),
			To:      sqlTableOwnerSummary(owners),
			Message: fmt.Sprintf("SQL statement references tables owned by more than %d module(s) by analysis policy %q", rule.MaxOwnersPerStatement, rule.Name),
		})
	}
	return violations
}

func sqlStatements(sql string) []sqlStatement {
	var statements []sqlStatement
	line := 1
	start := 0
	for i := 0; i < len(sql); i++ {
		if sql[i] != ';' {
			continue
		}
		text := sql[start : i+1]
		if strings.TrimSpace(text) != "" {
			statements = append(statements, sqlStatement{Text: text, Line: line})
		}
		line += strings.Count(text, "\n")
		start = i + 1
	}
	if start < len(sql) {
		text := sql[start:]
		if strings.TrimSpace(text) != "" {
			statements = append(statements, sqlStatement{Text: text, Line: line})
		}
	}
	return statements
}

func sqlTableReferences(sql string) []sqlTableReference {
	search := stripSQLCommentsPreserveLines(sql)
	matches := sqlTablePattern.FindAllStringSubmatchIndex(search, -1)
	refs := make([]sqlTableReference, 0, len(matches))
	for _, match := range matches {
		tableStart, tableEnd := sqlTableMatchRange(match)
		if tableStart < 0 || tableEnd < 0 || tableStart >= tableEnd {
			continue
		}
		table := normalizeSQLTable(search[tableStart:tableEnd])
		if table == "" {
			continue
		}
		refs = append(refs, sqlTableReference{Table: table, Line: 1 + strings.Count(search[:tableStart], "\n")})
	}
	return refs
}

func sqlTableMatchRange(match []int) (int, int) {
	for i := 2; i+1 < len(match); i += 2 {
		if match[i] >= 0 && match[i+1] >= 0 {
			return match[i], match[i+1]
		}
	}
	return -1, -1
}

func stripSQLCommentsPreserveLines(sql string) string {
	var b strings.Builder
	b.Grow(len(sql))
	inLineComment := false
	inBlockComment := false
	for i := 0; i < len(sql); i++ {
		ch := sql[i]
		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if inBlockComment {
			if ch == '*' && i+1 < len(sql) && sql[i+1] == '/' {
				b.WriteString("  ")
				i++
				inBlockComment = false
				continue
			}
			if ch == '\n' {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if ch == '-' && i+1 < len(sql) && sql[i+1] == '-' {
			b.WriteString("  ")
			i++
			inLineComment = true
			continue
		}
		if ch == '/' && i+1 < len(sql) && sql[i+1] == '*' {
			b.WriteString("  ")
			i++
			inBlockComment = true
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func sqlTableOwnerSummary(owners map[string]map[string]struct{}) string {
	parts := make([]string, 0, len(owners))
	for owner, tables := range owners {
		for table := range tables {
			parts = append(parts, table+" ("+owner+")")
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func sqlFilePosition(relPath string, line int) string {
	if line <= 0 {
		return relPath
	}
	return fmt.Sprintf("%s:%d", relPath, line)
}

func tableOwnerTargetConfigured(target TableOwnerTargetConfig) bool {
	return target.Module != "" || len(target.Modules) > 0
}

func tableOwnerTargetMatches(target TableOwnerTargetConfig, owner string) bool {
	return matchesTargetValue(target.Module, target.Modules, owner)
}
