package guard

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"
)

const (
	profileModularMonolith      = "modular-monolith"
	ruleExportedAPIExternalType = "exported-api-external-type"
	portsLayerName              = "ports"
)

type externalTypeRef struct {
	PackagePath string
	Name        string
}

func AnalysisRequiresSyntax(cfg Config) bool {
	return len(cfg.Analysis.Profiles) > 0
}

func CheckLoadedPackages(cfg Config, pkgs []LoadedPackage) ([]Violation, error) {
	violations := Check(cfg, ImportEdges(pkgs))
	profileViolations, err := CheckProfiles(cfg, pkgs)
	if err != nil {
		return nil, err
	}
	violations = append(violations, profileViolations...)
	sortViolations(violations)
	return violations, nil
}

func CheckProfiles(cfg Config, pkgs []LoadedPackage) ([]Violation, error) {
	var violations []Violation
	for _, profile := range enabledAnalysisProfiles(cfg) {
		switch profile {
		case profileModularMonolith:
			violations = append(violations, checkExportedAPIExternalTypes(cfg, pkgs)...)
		default:
			return nil, fmt.Errorf("unknown analysis profile %q", profile)
		}
	}
	sortViolations(violations)
	return violations, nil
}

func enabledAnalysisProfiles(cfg Config) []string {
	profiles := cfg.AnalysisProfiles()
	seen := make(map[string]struct{}, len(profiles))
	var enabled []string
	for _, profile := range profiles {
		profile = strings.TrimSpace(profile)
		if profile == "" {
			continue
		}
		if _, ok := seen[profile]; ok {
			continue
		}
		seen[profile] = struct{}{}
		enabled = append(enabled, profile)
	}
	return enabled
}

func checkExportedAPIExternalTypes(cfg Config, pkgs []LoadedPackage) []Violation {
	var violations []Violation
	for _, pkg := range pkgs {
		info := classifyLoadedPackage(cfg, pkg)
		if info.Layer != portsLayerName || pkg.Types == nil || pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				violations = append(violations, exportedDeclExternalTypeViolations(cfg, pkg, decl)...)
			}
		}
	}
	sortViolations(violations)
	return violations
}

func classifyLoadedPackage(cfg Config, pkg LoadedPackage) packageInfo {
	return classifyEdgeFrom(cfg, ImportEdge{
		From:        pkg.ImportPath,
		FromRelPath: pkg.RelPath,
		Test:        pkg.Test,
	})
}

func exportedDeclExternalTypeViolations(cfg Config, pkg LoadedPackage, decl ast.Decl) []Violation {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Name == nil || !ast.IsExported(d.Name.Name) {
			return nil
		}
		return externalTypeViolationsForObject(cfg, pkg, d.Name, d.Name.Name)
	case *ast.GenDecl:
		var violations []Violation
		for _, spec := range d.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				if s.Name != nil && ast.IsExported(s.Name.Name) {
					violations = append(violations, externalTypeViolationsForObject(cfg, pkg, s.Name, s.Name.Name)...)
				}
			case *ast.ValueSpec:
				for _, name := range s.Names {
					if name != nil && ast.IsExported(name.Name) {
						violations = append(violations, externalTypeViolationsForObject(cfg, pkg, name, name.Name)...)
					}
				}
			}
		}
		return violations
	default:
		return nil
	}
}

func externalTypeViolationsForObject(cfg Config, pkg LoadedPackage, ident *ast.Ident, name string) []Violation {
	obj := pkg.TypesInfo.Defs[ident]
	if obj == nil {
		return nil
	}
	refs := externalTypeRefs(obj.Type(), pkg.Types, cfg.Packages.Root)
	if len(refs) == 0 {
		return nil
	}
	return []Violation{{
		Rule:    ruleExportedAPIExternalType,
		From:    positionString(pkg, ident.Pos()),
		To:      externalTypeRefsString(refs),
		Message: fmt.Sprintf("exported ports API %q references external dependency type(s)", name),
	}}
}

func externalTypeRefs(t types.Type, current *types.Package, root string) []externalTypeRef {
	refs := make(map[string]externalTypeRef)
	seen := make(map[types.Type]struct{})

	var visit func(types.Type)
	visit = func(t types.Type) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}

		switch tt := t.(type) {
		case *types.Named:
			obj := tt.Obj()
			if obj != nil && obj.Pkg() != nil && obj.Pkg() != current && isExternalPackage(root, obj.Pkg().Path()) {
				key := obj.Pkg().Path() + "." + obj.Name()
				refs[key] = externalTypeRef{PackagePath: obj.Pkg().Path(), Name: obj.Name()}
			}
			if args := tt.TypeArgs(); args != nil {
				for i := 0; i < args.Len(); i++ {
					visit(args.At(i))
				}
			}
			if obj == nil || obj.Pkg() == nil || obj.Pkg() == current {
				visit(tt.Underlying())
			}
		case *types.Basic:
			return
		case *types.Pointer:
			visit(tt.Elem())
		case *types.Slice:
			visit(tt.Elem())
		case *types.Array:
			visit(tt.Elem())
		case *types.Map:
			visit(tt.Key())
			visit(tt.Elem())
		case *types.Chan:
			visit(tt.Elem())
		case *types.Tuple:
			for i := 0; i < tt.Len(); i++ {
				visit(tt.At(i).Type())
			}
		case *types.Signature:
			if params := tt.TypeParams(); params != nil {
				for i := 0; i < params.Len(); i++ {
					visit(params.At(i))
				}
			}
			visit(tt.Params())
			visit(tt.Results())
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				field := tt.Field(i)
				if field.Exported() {
					visit(field.Type())
				}
			}
		case *types.Interface:
			for i := 0; i < tt.NumExplicitMethods(); i++ {
				visit(tt.ExplicitMethod(i).Type())
			}
			tt.Complete()
			for i := 0; i < tt.NumEmbeddeds(); i++ {
				visit(tt.EmbeddedType(i))
			}
		case *types.TypeParam:
			visit(tt.Constraint())
		case *types.Union:
			for i := 0; i < tt.Len(); i++ {
				visit(tt.Term(i).Type())
			}
		}
	}

	visit(t)

	result := make([]externalTypeRef, 0, len(refs))
	for _, ref := range refs {
		result = append(result, ref)
	}
	sort.Slice(result, func(i, j int) bool {
		return externalTypeRefString(result[i]) < externalTypeRefString(result[j])
	})
	return result
}

func isExternalPackage(root, packagePath string) bool {
	root = strings.TrimSuffix(root, "/")
	if packagePath == "" || packagePath == root || strings.HasPrefix(packagePath, root+"/") {
		return false
	}
	first, _, _ := strings.Cut(packagePath, "/")
	return strings.Contains(first, ".")
}

func externalTypeRefsString(refs []externalTypeRef) string {
	parts := make([]string, len(refs))
	for i, ref := range refs {
		parts[i] = externalTypeRefString(ref)
	}
	return strings.Join(parts, ", ")
}

func externalTypeRefString(ref externalTypeRef) string {
	if ref.Name == "" {
		return ref.PackagePath
	}
	return ref.PackagePath + "." + ref.Name
}

func positionString(pkg LoadedPackage, pos token.Pos) string {
	if pkg.Fset == nil || pos == token.NoPos {
		return pkg.RelPath
	}
	position := pkg.Fset.Position(pos)
	if position.Filename == "" {
		return pkg.RelPath
	}
	path := filepath.ToSlash(filepath.Join(pkg.RelPath, filepath.Base(position.Filename)))
	if position.Line == 0 {
		return path
	}
	return fmt.Sprintf("%s:%d", path, position.Line)
}
