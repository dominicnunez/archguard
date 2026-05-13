package guard

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

var ErrViolationsFound = errors.New("boundary violations found")

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
}

func Check(cfg Config, edges []ImportEdge) []Violation {
	var violations []Violation
	for _, edge := range edges {
		from := classifyPackage(cfg, edge.From)
		to := classifyPackage(cfg, edge.To)
		if !from.Internal || !to.Internal || ignored(cfg, from) || ignored(cfg, to) || allowed(cfg, from, to) {
			continue
		}

		for _, rule := range cfg.Rules {
			if !selectorMatches(rule.From, from) || !denies(rule.Deny, from, to) {
				continue
			}
			violations = append(violations, Violation{
				Rule:    rule.Name,
				From:    from.RelPath,
				To:      to.RelPath,
				Message: denyMessage(rule.Deny),
			})
		}
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Rule != violations[j].Rule {
			return violations[i].Rule < violations[j].Rule
		}
		if violations[i].From != violations[j].From {
			return violations[i].From < violations[j].From
		}
		return violations[i].To < violations[j].To
	})
	return violations
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
	if selector.Module != "" && !wildcardMatch(selector.Module, info.Module) {
		return false
	}
	if selector.Layer != "" && !wildcardMatch(selector.Layer, info.Layer) {
		return false
	}
	if selector.Path != "" && !pathSelectorMatches(selector.Path, info) {
		return false
	}
	return selector.Module != "" || selector.Layer != "" || selector.Path != ""
}

func denies(deny DenyConfig, from, to packageInfo) bool {
	if deny.ExceptSameModule && from.Module != "" && from.Module == to.Module {
		return false
	}
	if len(deny.Modules) > 0 && to.Module != "" && matchesAny(deny.Modules, to.Module) {
		return true
	}
	if len(deny.Layers) > 0 && to.Layer != "" && matchesAny(deny.Layers, to.Layer) {
		return true
	}
	if len(deny.Paths) > 0 && matchesAny(deny.Paths, to.RelPath) {
		return true
	}
	return false
}

func allowed(cfg Config, from, to packageInfo) bool {
	for _, allow := range cfg.Allow {
		if pathSelectorMatches(allow.From, from) && pathSelectorMatches(allow.To, to) {
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

func denyMessage(deny DenyConfig) string {
	var parts []string
	if len(deny.Modules) > 0 {
		parts = append(parts, fmt.Sprintf("target modules %v are denied", deny.Modules))
	}
	if len(deny.Layers) > 0 {
		parts = append(parts, fmt.Sprintf("target layers %v are denied", deny.Layers))
	}
	if len(deny.Paths) > 0 {
		parts = append(parts, fmt.Sprintf("target paths %v are denied", deny.Paths))
	}
	if deny.ExceptSameModule {
		parts = append(parts, "except within the same module")
	}
	return strings.Join(parts, "; ")
}
