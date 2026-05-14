package guard

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
)

type ImportEdge struct {
	From        string
	FromRelPath string
	To          string
	Test        bool
}

type LoadOptions struct {
	IncludeTests bool
	NeedSyntax   bool
}

type LoadedPackage struct {
	ID         string
	ImportPath string
	Name       string
	ForTest    string
	RelPath    string
	Test       bool
	Imports    map[string]*packages.Package
	Syntax     []*ast.File
	Fset       *token.FileSet
}

func LoadImportGraph(dir string, patterns []string) ([]ImportEdge, error) {
	return LoadImportGraphWithOptions(dir, patterns, LoadOptions{})
}

func LoadImportGraphWithOptions(dir string, patterns []string, opts LoadOptions) ([]ImportEdge, error) {
	pkgs, err := LoadPackages(dir, patterns, opts)
	if err != nil {
		return nil, err
	}

	var edges []ImportEdge
	seen := make(map[importEdgeKey]struct{})
	for _, pkg := range pkgs {
		for importPath := range pkg.Imports {
			edge := ImportEdge{From: pkg.ImportPath, FromRelPath: pkg.RelPath, To: importPath, Test: pkg.Test}
			key := importEdgeKey{From: edge.From, FromRelPath: edge.FromRelPath, To: edge.To}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			edges = append(edges, edge)
		}
	}
	return edges, nil
}

type importEdgeKey struct {
	From        string
	FromRelPath string
	To          string
}

func LoadPackages(dir string, patterns []string, opts LoadOptions) ([]LoadedPackage, error) {
	mode := packages.LoadImports
	if opts.NeedSyntax {
		mode = packages.LoadSyntax | packages.NeedModule
	}
	cfg := &packages.Config{
		Dir:   dir,
		Mode:  mode,
		Tests: opts.IncludeTests,
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("load packages: %w", err)
	}

	var loadErrors []string
	for _, pkg := range pkgs {
		for _, pkgErr := range pkg.Errors {
			loadErrors = append(loadErrors, pkgErr.Error())
		}
	}
	if len(loadErrors) > 0 {
		return nil, fmt.Errorf("load packages: %s", strings.Join(loadErrors, "; "))
	}

	var loaded []LoadedPackage
	for _, pkg := range pkgs {
		if packageIsGeneratedTestMain(pkg) {
			continue
		}
		importPath := pkg.PkgPath
		if importPath == "" {
			importPath = packageIDBase(pkg.ID)
		}
		loaded = append(loaded, LoadedPackage{
			ID:         pkg.ID,
			ImportPath: importPath,
			Name:       pkg.Name,
			ForTest:    pkg.ForTest,
			RelPath:    packageRelPath(dir, pkg),
			Test:       packageIsTest(pkg),
			Imports:    pkg.Imports,
			Syntax:     pkg.Syntax,
			Fset:       pkg.Fset,
		})
	}
	return loaded, nil
}

func packageRelPath(dir string, pkg *packages.Package) string {
	files := pkg.GoFiles
	if len(files) == 0 {
		files = pkg.CompiledGoFiles
	}
	if len(files) == 0 {
		return ""
	}
	file := files[0]
	if !filepath.IsAbs(file) {
		file = filepath.Join(dir, file)
	}
	rel, err := filepath.Rel(dir, filepath.Dir(file))
	if err != nil {
		return ""
	}
	return filepath.ToSlash(rel)
}

func packageIsTest(pkg *packages.Package) bool {
	if pkg.ForTest != "" || strings.HasSuffix(pkg.PkgPath, "_test") || strings.Contains(pkg.ID, "[") {
		return true
	}
	for _, file := range append(append([]string{}, pkg.GoFiles...), pkg.CompiledGoFiles...) {
		if strings.HasSuffix(file, "_test.go") {
			return true
		}
	}
	return false
}

func packageIsGeneratedTestMain(pkg *packages.Package) bool {
	return pkg.ForTest == "" && strings.HasSuffix(pkg.ID, ".test")
}

func packageIDBase(id string) string {
	if before, _, ok := strings.Cut(id, " "); ok {
		return before
	}
	return id
}
