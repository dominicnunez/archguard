package guard

import (
	"errors"
	"sort"
	"strings"
)

var ErrViolationsFound = errors.New("boundary violations found")

const rulePolicyDeny = "policy-deny"

type Violation struct {
	Rule    string
	From    string
	To      string
	Message string
}

type packageInfo struct {
	ImportPath string
	RelPath    string
	Module     string
	Layer      string
	Internal   bool
	Test       bool
}

func Check(cfg Config, edges []ImportEdge) []Violation {
	var violations []Violation
	for _, edge := range edges {
		from := classifyEdgeFrom(cfg, edge)
		to := classifyPackage(cfg, edge.To)
		if !from.Internal || !to.Internal || ignored(cfg, from) || ignored(cfg, to) || policyAllows(cfg, from, to) {
			continue
		}
		violations = append(violations, Violation{
			Rule:    rulePolicyDeny,
			From:    from.RelPath,
			To:      to.RelPath,
			Message: "internal import is not allowed by policy",
		})
	}

	sortViolations(violations)
	return violations
}

func sortViolations(violations []Violation) {
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Rule != violations[j].Rule {
			return violations[i].Rule < violations[j].Rule
		}
		if violations[i].From != violations[j].From {
			return violations[i].From < violations[j].From
		}
		return violations[i].To < violations[j].To
	})
}

func dedupeViolations(violations []Violation) []Violation {
	if len(violations) == 0 {
		return nil
	}
	seen := make(map[Violation]struct{}, len(violations))
	unique := make([]Violation, 0, len(violations))
	for _, violation := range violations {
		if _, ok := seen[violation]; ok {
			continue
		}
		seen[violation] = struct{}{}
		unique = append(unique, violation)
	}
	return unique
}

func classifyEdgeFrom(cfg Config, edge ImportEdge) packageInfo {
	info := classifyPackage(cfg, edge.From)
	info.Test = edge.Test
	if !edge.Test || edge.FromRelPath == "" {
		return info
	}
	fromRel := strings.Trim(edge.FromRelPath, "/")
	if fromRel == "" || fromRel == "." {
		return info
	}
	info.RelPath = fromRel
	info.Internal = true
	module := longestMatchingModule(cfg.Modules, fromRel)
	if module == nil {
		info.Module = ""
		info.Layer = ""
		return info
	}
	info.Module = module.Name
	modulePath := strings.Trim(module.Path, "/")
	suffix := strings.TrimPrefix(fromRel, modulePath)
	suffix = strings.TrimPrefix(suffix, "/")
	info.Layer = matchingLayer(cfg.Layers, suffix)
	return info
}

func classifyPackage(cfg Config, importPath string) packageInfo {
	root := strings.TrimSuffix(cfg.Packages.Root, "/")
	if importPath != root && !strings.HasPrefix(importPath, root+"/") {
		return packageInfo{ImportPath: importPath}
	}

	relPath := strings.TrimPrefix(importPath, root)
	relPath = strings.TrimPrefix(relPath, "/")
	if relPath == "" {
		relPath = "."
	}

	info := packageInfo{ImportPath: importPath, RelPath: relPath, Internal: true}
	module := longestMatchingModule(cfg.Modules, relPath)
	if module == nil {
		return info
	}
	info.Module = module.Name

	modulePath := strings.Trim(module.Path, "/")
	suffix := strings.TrimPrefix(relPath, modulePath)
	suffix = strings.TrimPrefix(suffix, "/")
	info.Layer = matchingLayer(cfg.Layers, suffix)
	return info
}

func longestMatchingModule(modules []ModuleConfig, relPath string) *ModuleConfig {
	var selected *ModuleConfig
	for i := range modules {
		modulePath := strings.Trim(modules[i].Path, "/")
		if relPath != modulePath && !strings.HasPrefix(relPath, modulePath+"/") {
			continue
		}
		if selected == nil || len(modulePath) > len(strings.Trim(selected.Path, "/")) {
			selected = &modules[i]
		}
	}
	return selected
}

func matchingLayer(layers []LayerConfig, moduleSuffix string) string {
	for _, layer := range layers {
		layerPath := strings.Trim(layer.Path, "/")
		if moduleSuffix == layerPath || strings.HasPrefix(moduleSuffix, layerPath+"/") {
			return layer.Name
		}
	}
	return ""
}

func selectorMatches(selector Selector, info packageInfo) bool {
	if selector.Tests != nil && *selector.Tests != info.Test {
		return false
	}
	if selector.Module != "" && !wildcardMatch(selector.Module, info.Module) {
		return false
	}
	if selector.Layer != "" && !wildcardMatch(selector.Layer, info.Layer) {
		return false
	}
	if selector.Path != "" && !pathSelectorMatches(selector.Path, info) {
		return false
	}
	return selectorConfigured(selector)
}

func policyAllows(cfg Config, from, to packageInfo) bool {
	for _, allow := range cfg.Policy.Allow {
		if selectorMatches(allow.From, from) && targetMatches(allow.To, from, to) {
			return true
		}
	}
	return false
}

func targetMatches(target TargetSelector, from, to packageInfo) bool {
	if target.Internal && !to.Internal {
		return false
	}
	if target.SameModule && (from.Module == "" || from.Module != to.Module) {
		return false
	}
	if !matchesTargetValue(target.Module, target.Modules, to.Module) {
		return false
	}
	if !matchesTargetValue(target.Layer, target.Layers, to.Layer) {
		return false
	}
	if !matchesTargetPath(target, to) {
		return false
	}
	return targetSelectorConfigured(target)
}

func matchesTargetValue(single string, many []string, value string) bool {
	if single == "" && len(many) == 0 {
		return true
	}
	if value == "" {
		return false
	}
	if single != "" && wildcardMatch(single, value) {
		return true
	}
	return len(many) > 0 && matchesAny(many, value)
}

func matchesTargetPath(target TargetSelector, info packageInfo) bool {
	if target.Path == "" && len(target.Paths) == 0 {
		return true
	}
	if target.Path != "" && pathSelectorMatches(target.Path, info) {
		return true
	}
	for _, path := range target.Paths {
		if pathSelectorMatches(path, info) {
			return true
		}
	}
	return false
}

func ignored(cfg Config, info packageInfo) bool {
	for _, ignore := range cfg.Ignore {
		if pathSelectorMatches(ignore.Path, info) {
			return true
		}
	}
	return false
}

func pathSelectorMatches(pattern string, info packageInfo) bool {
	return wildcardMatch(pattern, info.RelPath) || wildcardMatch(pattern, info.ImportPath)
}
