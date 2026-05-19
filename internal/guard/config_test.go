package guard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".archguard.yaml")
	data := []byte(`version: 1
packages:
  root: example.com/app
modules:
  - name: token
    path: internal/token
layers:
  - name: app
    path: app
policy:
  default: deny
  allow:
  - name: app-internal
    from:
      layer: app
    to:
      internal: true
analysis:
  include_tests: true
  profiles:
    - modular-monolith
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.Packages.Root != "example.com/app" {
		t.Fatalf("packages.root = %q; want example.com/app", cfg.Packages.Root)
	}
	if got := cfg.PackagePatterns(); len(got) != 1 || got[0] != defaultPackagePattern {
		t.Fatalf("PackagePatterns() = %v; want [%s]", got, defaultPackagePattern)
	}
	if !cfg.Analysis.IncludeTests {
		t.Fatalf("analysis.include_tests = false; want true")
	}
	if got := cfg.AnalysisProfiles(); len(got) != 1 || got[0] != "modular-monolith" {
		t.Fatalf("AnalysisProfiles() = %v; want [modular-monolith]", got)
	}
}

func TestLoadConfigJSONC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".archguard.jsonc")
	data := []byte(`{
  // Required config version.
  "version": 1,
  "packages": {"root": "example.com/app", "patterns": ["./internal/..."]},
  "modules": [{"name": "token", "path": "internal/token"}],
  "policy": {"default": "deny", "allow": [{"name": "same-module", "from": {"module": "*"}, "to": {"same_module": true}}]},
  "analysis": {"include_tests": true, "profiles": ["modular-monolith"]},
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if got := cfg.PackagePatterns(); len(got) != 1 || got[0] != "./internal/..." {
		t.Fatalf("PackagePatterns() = %v; want [./internal/...]", got)
	}
	if !cfg.Analysis.IncludeTests {
		t.Fatalf("analysis.include_tests = false; want true")
	}
}

func TestLoadConfigRejectsJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".archguard.json")
	data := []byte(`{"version": 1, "packages": {"root": "example.com/app"}, "policy": {"default": "deny", "allow": [{"name": "same-module", "from": {"module": "*"}, "to": {"same_module": true}}]}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := LoadConfig(path); err == nil {
		t.Fatalf("LoadConfig() error = nil; want error")
	}
}

func TestFindConfigPrefersNonDotConfig(t *testing.T) {
	dir := t.TempDir()
	nonDot := filepath.Join(dir, "archguard.yml")
	dot := filepath.Join(dir, ".archguard.yaml")
	data := []byte("version: 1\npackages:\n  root: example.com/app\npolicy:\n  default: deny\n  allow:\n    - name: same-module\n      from:\n        module: '*'\n      to:\n        same_module: true\n")
	if err := os.WriteFile(nonDot, data, 0o600); err != nil {
		t.Fatalf("write non-dot config: %v", err)
	}
	if err := os.WriteFile(dot, data, 0o600); err != nil {
		t.Fatalf("write dot config: %v", err)
	}

	got, err := FindConfig(dir)
	if err != nil {
		t.Fatalf("FindConfig() error = %v", err)
	}
	if got != nonDot {
		t.Fatalf("FindConfig() = %q; want %q", got, nonDot)
	}
}

func TestLoadConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "missing policy", data: "version: 1\npackages:\n  root: example.com/app\n"},
		{name: "default allow", data: "version: 1\npackages:\n  root: example.com/app\npolicy:\n  default: allow\n  allow:\n    - name: same-module\n      from:\n        module: '*'\n      to:\n        same_module: true\n"},
		{name: "empty allow", data: "version: 1\npackages:\n  root: example.com/app\npolicy:\n  default: deny\n"},
		{name: "missing allow name", data: "version: 1\npackages:\n  root: example.com/app\npolicy:\n  default: deny\n  allow:\n    - from:\n        module: '*'\n      to:\n        same_module: true\n"},
		{name: "missing allow from", data: "version: 1\npackages:\n  root: example.com/app\npolicy:\n  default: deny\n  allow:\n    - name: bad\n      to:\n        same_module: true\n"},
		{name: "missing allow to", data: "version: 1\npackages:\n  root: example.com/app\npolicy:\n  default: deny\n  allow:\n    - name: bad\n      from:\n        module: '*'\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "archguard.yml")
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatalf("LoadConfig() error = nil; want error")
			}
		})
	}
}
