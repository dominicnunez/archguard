package guard

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
)

type ImportEdge struct {
	From string
	To   string
}

func LoadImportGraph(dir string, patterns []string) ([]ImportEdge, error) {
	cfg := &packages.Config{
		Dir:  dir,
		Mode: packages.NeedName | packages.NeedImports,
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

	var edges []ImportEdge
	for _, pkg := range pkgs {
		for importPath := range pkg.Imports {
			edges = append(edges, ImportEdge{From: pkg.PkgPath, To: importPath})
		}
	}
	return edges, nil
}
