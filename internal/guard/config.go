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
	IncludeTests     bool                    `json:"include_tests" yaml:"include_tests"`
	Profiles         []string                `json:"profiles" yaml:"profiles"`
	TableOwners      []TableOwnerConfig      `json:"table_owners" yaml:"table_owners"`
	ForbiddenImports []ForbiddenImportConfig `json:"forbidden_imports" yaml:"forbidden_imports"`
}

type TableOwnerConfig struct {
	Module string   `json:"module" yaml:"module"`
	Table  string   `json:"table" yaml:"table"`
	Tables []string `json:"tables" yaml:"tables"`
}

type ForbiddenImportConfig struct {
	Name     string   `json:"name" yaml:"name"`
	From     Selector `json:"from" yaml:"from"`
	Package  string   `json:"package" yaml:"package"`
	Packages []string `json:"packages" yaml:"packages"`
	Reason   string   `json:"reason" yaml:"reason"`
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
	for i, forbidden := range c.Analysis.ForbiddenImports {
		if forbidden.Name == "" {
			return fmt.Errorf("config analysis.forbidden_imports[%d].name is required", i)
		}
		if !selectorConfigured(forbidden.From) {
			return fmt.Errorf("config analysis.forbidden_imports[%d].from is required", i)
		}
		if forbidden.Package == "" && len(forbidden.Packages) == 0 {
			return fmt.Errorf("config analysis.forbidden_imports[%d].package or packages is required", i)
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
