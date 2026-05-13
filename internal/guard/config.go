package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const defaultPackagePattern = "./..."

type Config struct {
	Version  int            `json:"version" yaml:"version"`
	Packages PackagesConfig `json:"packages" yaml:"packages"`
	Modules  []ModuleConfig `json:"modules" yaml:"modules"`
	Layers   []LayerConfig  `json:"layers" yaml:"layers"`
	Rules    []RuleConfig   `json:"rules" yaml:"rules"`
	Allow    []AllowConfig  `json:"allow" yaml:"allow"`
	Ignore   []IgnoreConfig `json:"ignore" yaml:"ignore"`
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

type RuleConfig struct {
	Name string     `json:"name" yaml:"name"`
	From Selector   `json:"from" yaml:"from"`
	Deny DenyConfig `json:"deny" yaml:"deny"`
}

type Selector struct {
	Module string `json:"module" yaml:"module"`
	Layer  string `json:"layer" yaml:"layer"`
	Path   string `json:"path" yaml:"path"`
}

type DenyConfig struct {
	Modules          []string `json:"modules" yaml:"modules"`
	Layers           []string `json:"layers" yaml:"layers"`
	Paths            []string `json:"paths" yaml:"paths"`
	ExceptSameModule bool     `json:"except_same_module" yaml:"except_same_module"`
}

type AllowConfig struct {
	From   string `json:"from" yaml:"from"`
	To     string `json:"to" yaml:"to"`
	Reason string `json:"reason" yaml:"reason"`
}

type IgnoreConfig struct {
	Path   string `json:"path" yaml:"path"`
	Reason string `json:"reason" yaml:"reason"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	switch filepath.Ext(path) {
	case ".json":
		if err := json.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse json config %s: %w", path, err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse yaml config %s: %w", path, err)
		}
	default:
		return Config{}, fmt.Errorf("unsupported config extension %q", filepath.Ext(path))
	}

	if cfg.Packages.Root == "" {
		return Config{}, fmt.Errorf("config packages.root is required")
	}
	if len(cfg.Packages.Patterns) == 0 {
		cfg.Packages.Patterns = []string{defaultPackagePattern}
	}
	return cfg, nil
}

func FindConfig(dir string) (string, error) {
	for _, name := range []string{
		"gomodguard.yaml",
		"gomodguard.yml",
		"gomodguard.json",
		".gomodguard.yaml",
		".gomodguard.yml",
		".gomodguard.json",
	} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("stat config %s: %w", path, err)
		}
	}
	return "", fmt.Errorf("no gomodguard config found in %s", dir)
}

func (c Config) PackagePatterns() []string {
	patterns := make([]string, len(c.Packages.Patterns))
	copy(patterns, c.Packages.Patterns)
	return patterns
}
