package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"
)

const defaultPackagePattern = "./..."

type Config struct {
	Version  int            `json:"version" yaml:"version"`
	Packages PackagesConfig `json:"packages" yaml:"packages"`
	Modules  []ModuleConfig `json:"modules" yaml:"modules"`
	Layers   []LayerConfig  `json:"layers" yaml:"layers"`
	Policy   PolicyConfig   `json:"policy" yaml:"policy"`
	Ignore   []IgnoreConfig `json:"ignore" yaml:"ignore"`
	Analysis AnalysisConfig `json:"analysis" yaml:"analysis"`
}

type PackagesConfig struct {
	Root     string   `json:"root" yaml:"root"`
	Patterns []string `json:"patterns" yaml:"patterns"`
}

type ModuleConfig struct {
	Name string `json:"name" yaml:"name"`
	Path string `json:"path" yaml:"path"`
}

type LayerConfig struct {
	Name string `json:"name" yaml:"name"`
	Path string `json:"path" yaml:"path"`
}

type Selector struct {
	Module string `json:"module" yaml:"module"`
	Layer  string `json:"layer" yaml:"layer"`
	Path   string `json:"path" yaml:"path"`
	Tests  *bool  `json:"tests" yaml:"tests"`
}

type PolicyConfig struct {
	Default string              `json:"default" yaml:"default"`
	Allow   []PolicyAllowConfig `json:"allow" yaml:"allow"`
}

type PolicyAllowConfig struct {
	Name string         `json:"name" yaml:"name"`
	From Selector       `json:"from" yaml:"from"`
	To   TargetSelector `json:"to" yaml:"to"`
}

type TargetSelector struct {
	Internal   bool     `json:"internal" yaml:"internal"`
	SameModule bool     `json:"same_module" yaml:"same_module"`
	Module     string   `json:"module" yaml:"module"`
	Modules    []string `json:"modules" yaml:"modules"`
	Layer      string   `json:"layer" yaml:"layer"`
	Layers     []string `json:"layers" yaml:"layers"`
	Path       string   `json:"path" yaml:"path"`
	Paths      []string `json:"paths" yaml:"paths"`
}

type IgnoreConfig struct {
	Path   string `json:"path" yaml:"path"`
	Reason string `json:"reason" yaml:"reason"`
}

type AnalysisConfig struct {
	IncludeTests           bool                          `json:"include_tests" yaml:"include_tests"`
	Profiles               []string                      `json:"profiles" yaml:"profiles"`
	TableOwners            []TableOwnerConfig            `json:"table_owners" yaml:"table_owners"`
	ExternalImports        []ExternalImportConfig        `json:"external_imports" yaml:"external_imports"`
	ForbiddenImports       []ForbiddenImportConfig       `json:"forbidden_imports" yaml:"forbidden_imports"`
	ForbiddenExternalTypes []ForbiddenExternalTypeConfig `json:"forbidden_external_types" yaml:"forbidden_external_types"`
	ForbiddenInternalTypes []ForbiddenInternalTypeConfig `json:"forbidden_internal_types" yaml:"forbidden_internal_types"`
	SQLTableReferences     []SQLTableReferenceConfig     `json:"sql_table_references" yaml:"sql_table_references"`
	ProtocolBoundaries     []ProtocolBoundaryConfig      `json:"protocol_boundaries" yaml:"protocol_boundaries"`
	ProtocolTags           []ProtocolTagConfig           `json:"protocol_tags" yaml:"protocol_tags"`
	DependencyInjections   []DependencyInjectionConfig   `json:"dependency_injections" yaml:"dependency_injections"`
	ForbiddenTerms         []ForbiddenTermConfig         `json:"forbidden_terms" yaml:"forbidden_terms"`
}

type TableOwnerConfig struct {
	Module string   `json:"module" yaml:"module"`
	Table  string   `json:"table" yaml:"table"`
	Tables []string `json:"tables" yaml:"tables"`
}

type SQLTableReferenceConfig struct {
	Name                  string                 `json:"name" yaml:"name"`
	Path                  string                 `json:"path" yaml:"path"`
	Paths                 []string               `json:"paths" yaml:"paths"`
	IgnorePaths           []string               `json:"ignore_paths" yaml:"ignore_paths"`
	Allow                 TableOwnerTargetConfig `json:"allow" yaml:"allow"`
	Disallow              TableOwnerTargetConfig `json:"disallow" yaml:"disallow"`
	MaxOwnersPerStatement int                    `json:"max_owners_per_statement" yaml:"max_owners_per_statement"`
}

type TableOwnerTargetConfig struct {
	Module  string   `json:"module" yaml:"module"`
	Modules []string `json:"modules" yaml:"modules"`
}

type ExternalImportConfig struct {
	Name  string                    `json:"name" yaml:"name"`
	From  Selector                  `json:"from" yaml:"from"`
	Allow ExternalImportAllowConfig `json:"allow" yaml:"allow"`
}

type ExternalImportAllowConfig struct {
	Package  string   `json:"package" yaml:"package"`
	Packages []string `json:"packages" yaml:"packages"`
}

type ForbiddenImportConfig struct {
	Name     string         `json:"name" yaml:"name"`
	From     Selector       `json:"from" yaml:"from"`
	Disallow TargetSelector `json:"disallow" yaml:"disallow"`
}

type ForbiddenExternalTypeConfig struct {
	Name     string   `json:"name" yaml:"name"`
	From     Selector `json:"from" yaml:"from"`
	Package  string   `json:"package" yaml:"package"`
	Packages []string `json:"packages" yaml:"packages"`
}

type ForbiddenInternalTypeConfig struct {
	Name     string         `json:"name" yaml:"name"`
	From     Selector       `json:"from" yaml:"from"`
	Disallow TargetSelector `json:"disallow" yaml:"disallow"`
}

type ProtocolBoundaryConfig struct {
	Name            string         `json:"name" yaml:"name"`
	From            Selector       `json:"from" yaml:"from"`
	Disallow        TargetSelector `json:"disallow" yaml:"disallow"`
	ResponseSinks   []string       `json:"response_sinks" yaml:"response_sinks"`
	RequestDecoders []string       `json:"request_decoders" yaml:"request_decoders"`
	Docs            bool           `json:"docs" yaml:"docs"`
}

type ProtocolTagConfig struct {
	Name string   `json:"name" yaml:"name"`
	From Selector `json:"from" yaml:"from"`
}

type DependencyInjectionConfig struct {
	Name           string         `json:"name" yaml:"name"`
	From           Selector       `json:"from" yaml:"from"`
	Field          string         `json:"field" yaml:"field"`
	Fields         []string       `json:"fields" yaml:"fields"`
	ConsumerModule string         `json:"consumer_module" yaml:"consumer_module"`
	Disallow       TargetSelector `json:"disallow" yaml:"disallow"`
}

type ForbiddenTermConfig struct {
	Name        string   `json:"name" yaml:"name"`
	From        Selector `json:"from" yaml:"from"`
	Terms       []string `json:"terms" yaml:"terms"`
	Identifiers bool     `json:"identifiers" yaml:"identifiers"`
	Strings     bool     `json:"strings" yaml:"strings"`
	Comments    bool     `json:"comments" yaml:"comments"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	switch filepath.Ext(path) {
	case ".jsonc":
		data, err = hujson.Standardize(data)
		if err != nil {
			return Config{}, fmt.Errorf("parse jsonc config %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse jsonc config %s: %w", path, err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse yaml config %s: %w", path, err)
		}
	default:
		return Config{}, fmt.Errorf("unsupported config extension %q", filepath.Ext(path))
	}

	if len(cfg.Packages.Patterns) == 0 {
		cfg.Packages.Patterns = []string{defaultPackagePattern}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Packages.Root == "" {
		return fmt.Errorf("config packages.root is required")
	}
	if c.Policy.Default != "deny" {
		return fmt.Errorf("config policy.default must be \"deny\"")
	}
	if len(c.Policy.Allow) == 0 {
		return fmt.Errorf("config policy.allow must contain at least one rule")
	}
	for i, allow := range c.Policy.Allow {
		if allow.Name == "" {
			return fmt.Errorf("config policy.allow[%d].name is required", i)
		}
		if !selectorConfigured(allow.From) {
			return fmt.Errorf("config policy.allow[%d].from is required", i)
		}
		if !targetSelectorConfigured(allow.To) {
			return fmt.Errorf("config policy.allow[%d].to is required", i)
		}
	}
	for i, owner := range c.Analysis.TableOwners {
		if owner.Module == "" {
			return fmt.Errorf("config analysis.table_owners[%d].module is required", i)
		}
		if owner.Table == "" && len(owner.Tables) == 0 {
			return fmt.Errorf("config analysis.table_owners[%d].table or tables is required", i)
		}
	}
	for i, rule := range c.Analysis.SQLTableReferences {
		if rule.Name == "" {
			return fmt.Errorf("config analysis.sql_table_references[%d].name is required", i)
		}
		if rule.Path == "" && len(rule.Paths) == 0 {
			return fmt.Errorf("config analysis.sql_table_references[%d].path or paths is required", i)
		}
		if rule.MaxOwnersPerStatement < 0 {
			return fmt.Errorf("config analysis.sql_table_references[%d].max_owners_per_statement must be non-negative", i)
		}
		if !tableOwnerTargetConfigured(rule.Allow) && !tableOwnerTargetConfigured(rule.Disallow) && rule.MaxOwnersPerStatement == 0 {
			return fmt.Errorf("config analysis.sql_table_references[%d] must configure allow, disallow, or max_owners_per_statement", i)
		}
	}
	for i, external := range c.Analysis.ExternalImports {
		if external.Name == "" {
			return fmt.Errorf("config analysis.external_imports[%d].name is required", i)
		}
		if !selectorConfigured(external.From) {
			return fmt.Errorf("config analysis.external_imports[%d].from is required", i)
		}
	}
	for i, forbidden := range c.Analysis.ForbiddenImports {
		if forbidden.Name == "" {
			return fmt.Errorf("config analysis.forbidden_imports[%d].name is required", i)
		}
		if !selectorConfigured(forbidden.From) {
			return fmt.Errorf("config analysis.forbidden_imports[%d].from is required", i)
		}
		if !targetSelectorConfigured(forbidden.Disallow) {
			return fmt.Errorf("config analysis.forbidden_imports[%d].disallow is required", i)
		}
	}
	for i, forbidden := range c.Analysis.ForbiddenExternalTypes {
		if forbidden.Name == "" {
			return fmt.Errorf("config analysis.forbidden_external_types[%d].name is required", i)
		}
		if !selectorConfigured(forbidden.From) {
			return fmt.Errorf("config analysis.forbidden_external_types[%d].from is required", i)
		}
		if forbidden.Package == "" && len(forbidden.Packages) == 0 {
			return fmt.Errorf("config analysis.forbidden_external_types[%d].package or packages is required", i)
		}
	}
	for i, forbidden := range c.Analysis.ForbiddenInternalTypes {
		if forbidden.Name == "" {
			return fmt.Errorf("config analysis.forbidden_internal_types[%d].name is required", i)
		}
		if !selectorConfigured(forbidden.From) {
			return fmt.Errorf("config analysis.forbidden_internal_types[%d].from is required", i)
		}
		if !targetSelectorConfigured(forbidden.Disallow) {
			return fmt.Errorf("config analysis.forbidden_internal_types[%d].disallow is required", i)
		}
	}
	for i, boundary := range c.Analysis.ProtocolBoundaries {
		if boundary.Name == "" {
			return fmt.Errorf("config analysis.protocol_boundaries[%d].name is required", i)
		}
		if !selectorConfigured(boundary.From) {
			return fmt.Errorf("config analysis.protocol_boundaries[%d].from is required", i)
		}
		if !targetSelectorConfigured(boundary.Disallow) {
			return fmt.Errorf("config analysis.protocol_boundaries[%d].disallow is required", i)
		}
		if len(boundary.ResponseSinks) == 0 && len(boundary.RequestDecoders) == 0 && !boundary.Docs {
			return fmt.Errorf("config analysis.protocol_boundaries[%d] must configure response_sinks, request_decoders, or docs", i)
		}
	}
	for i, tag := range c.Analysis.ProtocolTags {
		if tag.Name == "" {
			return fmt.Errorf("config analysis.protocol_tags[%d].name is required", i)
		}
		if !selectorConfigured(tag.From) {
			return fmt.Errorf("config analysis.protocol_tags[%d].from is required", i)
		}
	}
	for i, injection := range c.Analysis.DependencyInjections {
		if injection.Name == "" {
			return fmt.Errorf("config analysis.dependency_injections[%d].name is required", i)
		}
		if !selectorConfigured(injection.From) {
			return fmt.Errorf("config analysis.dependency_injections[%d].from is required", i)
		}
		if injection.Field == "" && len(injection.Fields) == 0 {
			return fmt.Errorf("config analysis.dependency_injections[%d].field or fields is required", i)
		}
		if !targetSelectorConfigured(injection.Disallow) {
			return fmt.Errorf("config analysis.dependency_injections[%d].disallow is required", i)
		}
	}
	for i, terms := range c.Analysis.ForbiddenTerms {
		if terms.Name == "" {
			return fmt.Errorf("config analysis.forbidden_terms[%d].name is required", i)
		}
		if !selectorConfigured(terms.From) {
			return fmt.Errorf("config analysis.forbidden_terms[%d].from is required", i)
		}
		if len(terms.Terms) == 0 {
			return fmt.Errorf("config analysis.forbidden_terms[%d].terms is required", i)
		}
	}
	return nil
}

func selectorConfigured(selector Selector) bool {
	return selector.Module != "" || selector.Layer != "" || selector.Path != "" || selector.Tests != nil
}

func targetSelectorConfigured(selector TargetSelector) bool {
	return selector.Internal || selector.SameModule || selector.Module != "" || len(selector.Modules) > 0 || selector.Layer != "" || len(selector.Layers) > 0 || selector.Path != "" || len(selector.Paths) > 0
}

func FindConfig(dir string) (string, error) {
	for _, name := range []string{
		"archguard.yaml",
		"archguard.yml",
		"archguard.jsonc",
		".archguard.yaml",
		".archguard.yml",
		".archguard.jsonc",
	} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("stat config %s: %w", path, err)
		}
	}
	return "", fmt.Errorf("no archguard config found in %s", dir)
}

func (c Config) PackagePatterns() []string {
	patterns := make([]string, len(c.Packages.Patterns))
	copy(patterns, c.Packages.Patterns)
	return patterns
}

func (c Config) AnalysisProfiles() []string {
	profiles := make([]string, len(c.Analysis.Profiles))
	copy(profiles, c.Analysis.Profiles)
	return profiles
}
