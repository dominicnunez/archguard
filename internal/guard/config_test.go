package guard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gomodguard.yaml")
	data := []byte(`version: 1
packages:
  root: example.com/app
modules:
  - name: token
    path: internal/token
layers:
  - name: app
    path: app
rules:
  - name: app-rule
    from:
      layer: app
    deny:
      modules: ["*"]
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
}

func TestLoadConfigJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gomodguard.json")
	data := []byte(`{
  "version": 1,
  "packages": {"root": "example.com/app", "patterns": ["./internal/..."]},
  "modules": [{"name": "token", "path": "internal/token"}]
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
}
