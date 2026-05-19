package guard

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	profileModularMonolith       = "modular-monolith"
	ruleExportedAPIExternalType  = "exported-api-external-type"
	ruleAppInterfaceExternalType = "app-interface-external-type"
	ruleProtocolDTOInPorts       = "protocol-dto-in-ports"
	rulePrimitiveTimeInPorts     = "primitive-time-in-ports"
	ruleBroadPortsFile           = "broad-ports-file"
	ruleBroadPortsInterface      = "broad-ports-interface"
	ruleAdapterEmbedsForeignPort = "adapter-embeds-foreign-port"
	ruleThinAdapterForwarding    = "thin-adapter-forwarding"
	ruleCompositionMutation      = "composition-root-mutation"
	ruleCompositionSetterCall    = "composition-root-setter-call"
	ruleCompositionDomainConvert = "composition-root-domain-conversion"
	ruleSQLCrossModuleTable      = "sql-cross-module-table"
	portsLayerName               = "ports"
	adaptersLayerName            = "adapters"
	maxPortsInterfacesPerFile    = 8
	maxPortsInterfaceMethods     = 8
	minThinAdapterForwarders     = 2
)

var (
	protocolTagKeys = []string{"json", "xml", "yaml", "form", "protobuf"}
	sqlTablePattern = regexp.MustCompile(`(?i)\b(?:from|join|update|into|truncate(?:\s+table)?)\s+([a-zA-Z_][a-zA-Z0-9_\.]*)`)
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
	violations = dedupeViolations(violations)
	return violations, nil
}

func CheckProfiles(cfg Config, pkgs []LoadedPackage) ([]Violation, error) {
	var violations []Violation
	for _, profile := range enabledAnalysisProfiles(cfg) {
		switch profile {
		case profileModularMonolith:
			violations = append(violations, checkExportedAPIExternalTypes(cfg, pkgs)...)
			violations = append(violations, checkAppInterfaceExternalTypes(cfg, pkgs)...)
			violations = append(violations, checkProtocolDTOsInPorts(cfg, pkgs)...)
			violations = append(violations, checkPrimitiveTimeFieldsInPorts(cfg, pkgs)...)
			violations = append(violations, checkBroadPortsSurfaces(cfg, pkgs)...)
			violations = append(violations, checkThinAdapters(cfg, pkgs)...)
			violations = append(violations, checkCompositionRootPatterns(cfg, pkgs)...)
			violations = append(violations, checkSQLTableOwnership(cfg, pkgs)...)
		default:
			return nil, fmt.Errorf("unknown analysis profile %q", profile)
		}
	}
	sortViolations(violations)
	violations = dedupeViolations(violations)
	return violations, nil
}

func checkAppInterfaceExternalTypes(cfg Config, pkgs []LoadedPackage) []Violation {
	var violations []Violation
	for _, pkg := range pkgs {
		info := classifyLoadedPackage(cfg, pkg)
		if info.Layer != "app" || pkg.Types == nil || pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				violations = append(violations, exportedInterfaceExternalTypeViolations(cfg, pkg, decl)...)
			}
		}
	}
	sortViolations(violations)
	return violations
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

func checkProtocolDTOsInPorts(cfg Config, pkgs []LoadedPackage) []Violation {
	var violations []Violation
	for _, pkg := range pkgs {
		info := classifyLoadedPackage(cfg, pkg)
		if info.Layer != portsLayerName {
			continue
		}
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				violations = append(violations, protocolDTOTypeViolations(pkg, decl)...)
			}
		}
	}
	sortViolations(violations)
	return violations
}

func checkPrimitiveTimeFieldsInPorts(cfg Config, pkgs []LoadedPackage) []Violation {
	var violations []Violation
	for _, pkg := range pkgs {
		info := classifyLoadedPackage(cfg, pkg)
		if info.Layer != portsLayerName || pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				violations = append(violations, primitiveTimeFieldViolations(pkg, decl)...)
			}
		}
	}
	sortViolations(violations)
	return violations
}

func checkBroadPortsSurfaces(cfg Config, pkgs []LoadedPackage) []Violation {
	var violations []Violation
	for _, pkg := range pkgs {
		info := classifyLoadedPackage(cfg, pkg)
		if info.Layer != portsLayerName {
			continue
		}
		for _, file := range pkg.Syntax {
			violations = append(violations, broadPortsFileViolations(pkg, file)...)
		}
	}
	sortViolations(violations)
	return violations
}

func checkThinAdapters(cfg Config, pkgs []LoadedPackage) []Violation {
	var violations []Violation
	for _, pkg := range pkgs {
		info := classifyLoadedPackage(cfg, pkg)
		if info.Layer != adaptersLayerName {
			continue
		}
		for _, file := range pkg.Syntax {
			violations = append(violations, adapterEmbeddedForeignPortViolations(cfg, pkg, info, file)...)
		}
		violations = append(violations, thinAdapterForwardingViolations(pkg, adapterForeignPortBackedFields(cfg, pkg, info))...)
	}
	sortViolations(violations)
	return violations
}

func checkCompositionRootPatterns(cfg Config, pkgs []LoadedPackage) []Violation {
	var violations []Violation
	for _, pkg := range pkgs {
		info := classifyLoadedPackage(cfg, pkg)
		if pkg.Test || !isCompositionRootPackage(info) || pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			violations = append(violations, compositionRootFileViolations(cfg, pkg, info, file)...)
		}
	}
	sortViolations(violations)
	return violations
}

func checkSQLTableOwnership(cfg Config, pkgs []LoadedPackage) []Violation {
	var violations []Violation
	for _, pkg := range pkgs {
		info := classifyLoadedPackage(cfg, pkg)
		if info.Layer != adaptersLayerName || !strings.Contains(info.RelPath, "/adapters/postgres") || info.Module == "" {
			continue
		}
		violations = append(violations, sqlTableOwnershipViolations(cfg, pkg, info)...)
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

func isCompositionRootPackage(info packageInfo) bool {
	return pathHasSegment(info.RelPath, "bootstrap") || info.RelPath == "internal/api" || strings.HasPrefix(info.RelPath, "cmd/")
}

func pathHasSegment(path, segment string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == segment {
			return true
		}
	}
	return false
}

func compositionRootFileViolations(cfg Config, pkg LoadedPackage, info packageInfo, file *ast.File) []Violation {
	var violations []Violation
	for _, decl := range file.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || funcDecl.Body == nil {
			continue
		}
		paramNames := funcParameterNameSet(funcDecl)
		ast.Inspect(funcDecl.Body, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.AssignStmt:
				violations = append(violations, compositionRootAssignmentViolations(pkg, n, paramNames)...)
			case *ast.CallExpr:
				if violation, ok := compositionSetterCallViolation(cfg, pkg, n); ok {
					violations = append(violations, violation)
				}
				if violation, ok := compositionDomainConversionViolation(cfg, pkg, info, n); ok {
					violations = append(violations, violation)
				}
			}
			return true
		})
	}
	return violations
}

func compositionRootAssignmentViolations(pkg LoadedPackage, assign *ast.AssignStmt, paramNames map[string]struct{}) []Violation {
	if len(paramNames) == 0 {
		return nil
	}
	var violations []Violation
	for _, lhs := range assign.Lhs {
		selector, ok := unparen(lhs).(*ast.SelectorExpr)
		if !ok {
			continue
		}
		root := selectorRootIdent(selector)
		if root == "" {
			continue
		}
		if _, ok := paramNames[root]; !ok {
			continue
		}
		violations = append(violations, Violation{
			Rule:    ruleCompositionMutation,
			From:    positionString(pkg, selector.Pos()),
			To:      root + "." + selector.Sel.Name,
			Message: "composition-root function mutates a collaborator after construction",
		})
	}
	return violations
}

func compositionSetterCallViolation(cfg Config, pkg LoadedPackage, call *ast.CallExpr) (Violation, bool) {
	selector, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel == nil || !isSetterName(selector.Sel.Name) || pkg.TypesInfo == nil {
		return Violation{}, false
	}
	obj, ok := pkg.TypesInfo.Uses[selector.Sel].(*types.Func)
	if !ok || obj.Pkg() == nil || !isInternalPackage(cfg, obj.Pkg().Path()) {
		return Violation{}, false
	}
	return Violation{
		Rule:    ruleCompositionSetterCall,
		From:    positionString(pkg, selector.Sel.Pos()),
		To:      obj.Pkg().Path() + "." + obj.Name(),
		Message: "composition root calls a Set-style method instead of passing dependencies at construction",
	}, true
}

func compositionDomainConversionViolation(cfg Config, pkg LoadedPackage, info packageInfo, call *ast.CallExpr) (Violation, bool) {
	typeName := callTypeName(pkg, call)
	if typeName == nil || typeName.Pkg() == nil {
		return Violation{}, false
	}
	target := classifyPackage(cfg, typeName.Pkg().Path())
	if !target.Internal || target.Layer != "domain" || target.Module == "" || target.Module == info.Module {
		return Violation{}, false
	}
	return Violation{
		Rule:    ruleCompositionDomainConvert,
		From:    positionString(pkg, call.Fun.Pos()),
		To:      target.RelPath + "." + typeName.Name(),
		Message: "composition root converts values into a domain type owned by another module",
	}, true
}

func sqlTableOwnershipViolations(cfg Config, pkg LoadedPackage, info packageInfo) []Violation {
	type seenKey struct {
		file  string
		table string
	}
	seen := make(map[seenKey]struct{})
	var violations []Violation
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if !looksLikeSQL(text) {
				return true
			}
			for _, table := range sqlTables(text) {
				owner := tableOwnerModule(cfg, table)
				if owner == "" || owner == info.Module {
					continue
				}
				filename := ""
				if pkg.Fset != nil {
					filename = filepath.ToSlash(pkg.Fset.Position(lit.Pos()).Filename)
				}
				key := seenKey{file: filename, table: table}
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				violations = append(violations, Violation{
					Rule:    ruleSQLCrossModuleTable,
					From:    positionString(pkg, lit.Pos()),
					To:      table + " (" + owner + ")",
					Message: "postgres adapter SQL references a table inferred to belong to another module",
				})
			}
			return true
		})
	}
	return violations
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

func exportedInterfaceExternalTypeViolations(cfg Config, pkg LoadedPackage, decl ast.Decl) []Violation {
	genDecl, ok := decl.(*ast.GenDecl)
	if !ok {
		return nil
	}
	var violations []Violation
	for _, spec := range genDecl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok || typeSpec.Name == nil || !ast.IsExported(typeSpec.Name.Name) {
			continue
		}
		if _, ok := typeSpec.Type.(*ast.InterfaceType); !ok {
			continue
		}
		refs := externalTypeViolationsForObject(cfg, pkg, typeSpec.Name, typeSpec.Name.Name)
		for _, violation := range refs {
			violation.Rule = ruleAppInterfaceExternalType
			violation.Message = fmt.Sprintf("exported app interface %q references external dependency type(s)", typeSpec.Name.Name)
			violations = append(violations, violation)
		}
	}
	return violations
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

func protocolDTOTypeViolations(pkg LoadedPackage, decl ast.Decl) []Violation {
	genDecl, ok := decl.(*ast.GenDecl)
	if !ok {
		return nil
	}
	var violations []Violation
	for _, spec := range genDecl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok || typeSpec.Name == nil || !ast.IsExported(typeSpec.Name.Name) {
			continue
		}
		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			continue
		}
		tags := protocolTags(structType)
		if len(tags) == 0 {
			continue
		}
		violations = append(violations, Violation{
			Rule:    ruleProtocolDTOInPorts,
			From:    positionString(pkg, typeSpec.Name.Pos()),
			To:      strings.Join(tags, ", "),
			Message: fmt.Sprintf("exported ports struct %q has protocol field tags", typeSpec.Name.Name),
		})
	}
	return violations
}

func primitiveTimeFieldViolations(pkg LoadedPackage, decl ast.Decl) []Violation {
	genDecl, ok := decl.(*ast.GenDecl)
	if !ok {
		return nil
	}
	var violations []Violation
	for _, spec := range genDecl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok || typeSpec.Name == nil || !ast.IsExported(typeSpec.Name.Name) {
			continue
		}
		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok || structType.Fields == nil {
			continue
		}
		for _, field := range structType.Fields.List {
			if !isPrimitiveTimeField(pkg, field) {
				continue
			}
			for _, name := range field.Names {
				violations = append(violations, Violation{
					Rule:    rulePrimitiveTimeInPorts,
					From:    positionString(pkg, name.Pos()),
					To:      typeSpec.Name.Name + "." + name.Name,
					Message: "exported ports struct uses primitive numeric time field instead of a domain time value",
				})
			}
		}
	}
	return violations
}

func broadPortsFileViolations(pkg LoadedPackage, file *ast.File) []Violation {
	var violations []Violation
	var exportedInterfaces []ast.Ident
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name == nil || !ast.IsExported(typeSpec.Name.Name) {
				continue
			}
			interfaceType, ok := typeSpec.Type.(*ast.InterfaceType)
			if !ok {
				continue
			}
			if isPersistencePortInterface(typeSpec.Name.Name) {
				continue
			}
			exportedInterfaces = append(exportedInterfaces, *typeSpec.Name)
			methodCount := interfaceMethodCount(interfaceType)
			if methodCount > maxPortsInterfaceMethods {
				violations = append(violations, Violation{
					Rule:    ruleBroadPortsInterface,
					From:    positionString(pkg, typeSpec.Name.Pos()),
					To:      strconv.Itoa(methodCount),
					Message: fmt.Sprintf("exported ports interface %q has more than %d explicit methods", typeSpec.Name.Name, maxPortsInterfaceMethods),
				})
			}
		}
	}
	if len(exportedInterfaces) > maxPortsInterfacesPerFile {
		violations = append(violations, Violation{
			Rule:    ruleBroadPortsFile,
			From:    positionString(pkg, exportedInterfaces[0].Pos()),
			To:      strconv.Itoa(len(exportedInterfaces)),
			Message: fmt.Sprintf("ports file declares more than %d exported interfaces", maxPortsInterfacesPerFile),
		})
	}
	return violations
}

func isPersistencePortInterface(name string) bool {
	return strings.HasSuffix(name, "Repository") || strings.HasSuffix(name, "DataSource")
}

func adapterEmbeddedForeignPortViolations(cfg Config, pkg LoadedPackage, adapterInfo packageInfo, file *ast.File) []Violation {
	if pkg.TypesInfo == nil {
		return nil
	}
	var violations []Violation
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			interfaceType, ok := typeSpec.Type.(*ast.InterfaceType)
			if !ok {
				continue
			}
			for _, embedded := range embeddedForeignPorts(cfg, pkg, adapterInfo, interfaceType) {
				violations = append(violations, Violation{
					Rule:    ruleAdapterEmbedsForeignPort,
					From:    positionString(pkg, embedded.position),
					To:      embedded.info.RelPath + "." + embedded.typeName,
					Message: "adapter interface embeds a foreign module ports interface instead of declaring the local seam",
				})
			}
		}
	}
	return violations
}

type embeddedForeignPort struct {
	position token.Pos
	info     packageInfo
	typeName string
}

func embeddedForeignPorts(cfg Config, pkg LoadedPackage, adapterInfo packageInfo, interfaceType *ast.InterfaceType) []embeddedForeignPort {
	if pkg.TypesInfo == nil || interfaceType.Methods == nil {
		return nil
	}
	var embedded []embeddedForeignPort
	for _, field := range interfaceType.Methods.List {
		if len(field.Names) > 0 {
			continue
		}
		packagePath, typeName := selectorTypePackage(pkg, field.Type)
		if packagePath == "" {
			continue
		}
		embeddedInfo := classifyPackage(cfg, packagePath)
		if !embeddedInfo.Internal || embeddedInfo.Layer != portsLayerName || embeddedInfo.Module == "" || embeddedInfo.Module == adapterInfo.Module {
			continue
		}
		embedded = append(embedded, embeddedForeignPort{position: field.Pos(), info: embeddedInfo, typeName: typeName})
	}
	return embedded
}

func adapterForeignPortBackedFields(cfg Config, pkg LoadedPackage, adapterInfo packageInfo) map[forwardingKey]struct{} {
	interfaceNames := make(map[string]struct{})
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok || typeSpec.Name == nil {
					continue
				}
				interfaceType, ok := typeSpec.Type.(*ast.InterfaceType)
				if !ok || len(embeddedForeignPorts(cfg, pkg, adapterInfo, interfaceType)) == 0 {
					continue
				}
				interfaceNames[typeSpec.Name.Name] = struct{}{}
			}
		}
	}
	if len(interfaceNames) == 0 {
		return nil
	}

	fields := make(map[forwardingKey]struct{})
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok || typeSpec.Name == nil {
					continue
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok || structType.Fields == nil {
					continue
				}
				for _, field := range structType.Fields.List {
					fieldType := fieldTypeName(field.Type)
					if _, ok := interfaceNames[fieldType]; !ok {
						continue
					}
					for _, name := range field.Names {
						if name != nil {
							fields[forwardingKey{receiver: typeSpec.Name.Name, field: name.Name}] = struct{}{}
						}
					}
				}
			}
		}
	}
	return fields
}

type forwardingKey struct {
	receiver string
	field    string
}

type forwardingGroup struct {
	position token.Pos
	count    int
}

func thinAdapterForwardingViolations(pkg LoadedPackage, eligibleFields map[forwardingKey]struct{}) []Violation {
	if len(eligibleFields) == 0 {
		return nil
	}
	groups := make(map[forwardingKey]forwardingGroup)
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok || funcDecl.Name == nil {
				continue
			}
			receiverType := receiverTypeName(funcDecl)
			fieldName, ok := forwardedReceiverField(funcDecl)
			if receiverType == "" || !ok {
				continue
			}
			key := forwardingKey{receiver: receiverType, field: fieldName}
			if _, ok := eligibleFields[key]; !ok {
				continue
			}
			group := groups[key]
			if group.position == token.NoPos {
				group.position = funcDecl.Name.Pos()
			}
			group.count++
			groups[key] = group
		}
	}

	var violations []Violation
	for key, group := range groups {
		if group.count < minThinAdapterForwarders {
			continue
		}
		violations = append(violations, Violation{
			Rule:    ruleThinAdapterForwarding,
			From:    positionString(pkg, group.position),
			To:      strconv.Itoa(group.count),
			Message: fmt.Sprintf("adapter receiver %q directly forwards multiple methods to field %q", key.receiver, key.field),
		})
	}
	return violations
}

func interfaceMethodCount(interfaceType *ast.InterfaceType) int {
	if interfaceType.Methods == nil {
		return 0
	}
	count := 0
	for _, field := range interfaceType.Methods.List {
		count += len(field.Names)
	}
	return count
}

func selectorTypePackage(pkg LoadedPackage, expr ast.Expr) (string, string) {
	selector, ok := unparen(expr).(*ast.SelectorExpr)
	if !ok || selector.Sel == nil || pkg.TypesInfo == nil {
		return "", ""
	}
	obj := pkg.TypesInfo.Uses[selector.Sel]
	if obj == nil || obj.Pkg() == nil {
		return "", ""
	}
	return obj.Pkg().Path(), selector.Sel.Name
}

func fieldTypeName(expr ast.Expr) string {
	typeExpr := unparen(expr)
	if star, ok := typeExpr.(*ast.StarExpr); ok {
		typeExpr = unparen(star.X)
	}
	ident, ok := typeExpr.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

func receiverTypeName(funcDecl *ast.FuncDecl) string {
	if funcDecl.Recv == nil || len(funcDecl.Recv.List) == 0 {
		return ""
	}
	typeExpr := unparen(funcDecl.Recv.List[0].Type)
	if star, ok := typeExpr.(*ast.StarExpr); ok {
		typeExpr = unparen(star.X)
	}
	ident, ok := typeExpr.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

func forwardedReceiverField(funcDecl *ast.FuncDecl) (string, bool) {
	receiverName := receiverIdentName(funcDecl)
	if receiverName == "" || funcDecl.Body == nil || funcDecl.Name == nil {
		return "", false
	}
	call, ok := singleCallBody(funcDecl.Body)
	if !ok || !argumentsPassThrough(funcDecl.Type.Params, call.Args) {
		return "", false
	}
	methodSelector, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || methodSelector.Sel == nil || methodSelector.Sel.Name != funcDecl.Name.Name {
		return "", false
	}
	fieldSelector, ok := unparen(methodSelector.X).(*ast.SelectorExpr)
	if !ok || fieldSelector.Sel == nil {
		return "", false
	}
	base, ok := unparen(fieldSelector.X).(*ast.Ident)
	if !ok || base.Name != receiverName {
		return "", false
	}
	return fieldSelector.Sel.Name, true
}

func receiverIdentName(funcDecl *ast.FuncDecl) string {
	if funcDecl.Recv == nil || len(funcDecl.Recv.List) == 0 || len(funcDecl.Recv.List[0].Names) == 0 {
		return ""
	}
	return funcDecl.Recv.List[0].Names[0].Name
}

func singleCallBody(body *ast.BlockStmt) (*ast.CallExpr, bool) {
	if body == nil || len(body.List) != 1 {
		return nil, false
	}
	switch stmt := body.List[0].(type) {
	case *ast.ReturnStmt:
		if len(stmt.Results) != 1 {
			return nil, false
		}
		call, ok := unparen(stmt.Results[0]).(*ast.CallExpr)
		return call, ok
	case *ast.ExprStmt:
		call, ok := unparen(stmt.X).(*ast.CallExpr)
		return call, ok
	default:
		return nil, false
	}
}

func argumentsPassThrough(params *ast.FieldList, args []ast.Expr) bool {
	paramNames := parameterNames(params)
	if len(paramNames) != len(args) {
		return false
	}
	for i, arg := range args {
		ident, ok := unparen(arg).(*ast.Ident)
		if !ok || ident.Name != paramNames[i] {
			return false
		}
	}
	return true
}

func parameterNames(params *ast.FieldList) []string {
	if params == nil {
		return nil
	}
	var names []string
	for _, field := range params.List {
		for _, name := range field.Names {
			if name != nil {
				names = append(names, name.Name)
			}
		}
	}
	return names
}

func funcParameterNameSet(funcDecl *ast.FuncDecl) map[string]struct{} {
	names := make(map[string]struct{})
	for _, name := range parameterNames(funcDecl.Type.Params) {
		names[name] = struct{}{}
	}
	return names
}

func selectorRootIdent(selector *ast.SelectorExpr) string {
	var expr ast.Expr = selector
	for {
		s, ok := unparen(expr).(*ast.SelectorExpr)
		if !ok {
			break
		}
		expr = s.X
	}
	ident, ok := unparen(expr).(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

func isSetterName(name string) bool {
	return len(name) > len("Set") && strings.HasPrefix(name, "Set") && name[len("Set")] >= 'A' && name[len("Set")] <= 'Z'
}

func isInternalPackage(cfg Config, packagePath string) bool {
	root := strings.TrimSuffix(cfg.Packages.Root, "/")
	return packagePath == root || strings.HasPrefix(packagePath, root+"/")
}

func callTypeName(pkg LoadedPackage, call *ast.CallExpr) *types.TypeName {
	if pkg.TypesInfo == nil {
		return nil
	}
	switch fun := unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		if fun.Sel == nil {
			return nil
		}
		obj, _ := pkg.TypesInfo.Uses[fun.Sel].(*types.TypeName)
		return obj
	case *ast.Ident:
		obj, _ := pkg.TypesInfo.Uses[fun].(*types.TypeName)
		return obj
	default:
		return nil
	}
}

func sqlTables(sql string) []string {
	seen := make(map[string]struct{})
	var tables []string
	for _, match := range sqlTablePattern.FindAllStringSubmatch(sql, -1) {
		if len(match) < 2 {
			continue
		}
		table := normalizeSQLTable(match[1])
		if table == "" {
			continue
		}
		if _, ok := seen[table]; ok {
			continue
		}
		seen[table] = struct{}{}
		tables = append(tables, table)
	}
	return tables
}

func looksLikeSQL(text string) bool {
	upper := strings.ToUpper(strings.TrimSpace(text))
	if upper == "" {
		return false
	}
	if strings.HasPrefix(upper, "TRUNCATE ") {
		return true
	}
	for _, prefix := range []string{"SELECT ", "INSERT ", "UPDATE ", "DELETE ", "WITH "} {
		if !strings.HasPrefix(upper, prefix) {
			continue
		}
		return strings.Contains(upper, " FROM ") || strings.Contains(upper, " JOIN ") || strings.Contains(upper, " INTO ") || strings.Contains(upper, " SET ") || strings.Contains(upper, " WHERE ") || strings.Contains(upper, "$1")
	}
	return false
}

func normalizeSQLTable(table string) string {
	table = strings.Trim(strings.ToLower(table), `". ,;()\n\t`)
	if table == "" {
		return ""
	}
	if before, _, ok := strings.Cut(table, "("); ok {
		table = before
	}
	parts := strings.Split(table, ".")
	return strings.Trim(parts[len(parts)-1], `". ,;()`)
}

func tableOwnerModule(cfg Config, table string) string {
	if owner := configuredTableOwnerModule(cfg, table); owner != "" {
		return owner
	}
	for _, module := range cfg.Modules {
		if tableMatchesModule(table, module.Name) {
			return module.Name
		}
	}
	return ""
}

func configuredTableOwnerModule(cfg Config, table string) string {
	for _, owner := range cfg.Analysis.TableOwners {
		if owner.Table != "" && wildcardMatch(strings.ToLower(owner.Table), table) {
			return owner.Module
		}
		for _, pattern := range owner.Tables {
			if wildcardMatch(strings.ToLower(pattern), table) {
				return owner.Module
			}
		}
	}
	return ""
}

func tableMatchesModule(table, moduleName string) bool {
	moduleName = strings.ToLower(moduleName)
	for _, variant := range []string{moduleName, pluralModuleName(moduleName)} {
		if table == variant || strings.HasPrefix(table, variant+"_") {
			return true
		}
	}
	return false
}

func pluralModuleName(moduleName string) string {
	if strings.HasSuffix(moduleName, "s") {
		return moduleName
	}
	if strings.HasSuffix(moduleName, "y") {
		return strings.TrimSuffix(moduleName, "y") + "ies"
	}
	return moduleName + "s"
}

func unparen(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

func protocolTags(structType *ast.StructType) []string {
	if structType.Fields == nil {
		return nil
	}
	seen := make(map[string]struct{})
	for _, field := range structType.Fields.List {
		if field.Tag == nil {
			continue
		}
		tagText, err := strconv.Unquote(field.Tag.Value)
		if err != nil {
			continue
		}
		structTag := reflect.StructTag(tagText)
		for _, key := range protocolTagKeys {
			if value, ok := structTag.Lookup(key); ok && value != "-" {
				seen[key] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	tags := make([]string, 0, len(seen))
	for tag := range seen {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

func isPrimitiveTimeField(pkg LoadedPackage, field *ast.Field) bool {
	if len(field.Names) == 0 {
		return false
	}
	matchedName := false
	for _, name := range field.Names {
		if name != nil && ast.IsExported(name.Name) && isTimeLikeFieldName(name.Name) {
			matchedName = true
			break
		}
	}
	if !matchedName || pkg.TypesInfo == nil {
		return false
	}
	t := pkg.TypesInfo.TypeOf(field.Type)
	if t == nil {
		return false
	}
	for {
		ptr, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = ptr.Elem()
	}
	basic, ok := t.Underlying().(*types.Basic)
	if !ok {
		return false
	}
	switch basic.Kind() {
	case types.Int, types.Int8, types.Int16, types.Int32, types.Int64, types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64:
		return true
	default:
		return false
	}
}

func isTimeLikeFieldName(name string) bool {
	return strings.HasSuffix(name, "Timestamp") || strings.HasSuffix(name, "Time") || strings.HasSuffix(name, "At")
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
