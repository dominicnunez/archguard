package guard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckFindsForeignAdapterImport(t *testing.T) {
	cfg := testConfig()
	edges := []ImportEdge{
		{From: "example.com/app/internal/creator/app", To: "example.com/app/internal/market/adapters/postgres"},
	}

	violations := Check(cfg, edges)

	if len(violations) != 1 {
		t.Fatalf("Check() violations = %d; want 1", len(violations))
	}
	if violations[0].Rule != "app-no-foreign-adapters" {
		t.Fatalf("Rule = %q; want app-no-foreign-adapters", violations[0].Rule)
	}
}

func TestCheckAllowsSameModuleAdapterImport(t *testing.T) {
	cfg := testConfig()
	edges := []ImportEdge{
		{From: "example.com/app/internal/creator/app", To: "example.com/app/internal/creator/adapters/token"},
	}

	violations := Check(cfg, edges)

	if len(violations) != 0 {
		t.Fatalf("Check() violations = %d; want 0", len(violations))
	}
}

func TestCheckAllowsExplicitException(t *testing.T) {
	cfg := testConfig()
	cfg.Allow = []AllowConfig{
		{From: "internal/bootstrap", To: "internal/*/adapters/postgres", Reason: "composition root"},
	}
	cfg.Rules = append(cfg.Rules, RuleConfig{
		Name: "bootstrap-no-adapters",
		From: Selector{Path: "internal/bootstrap"},
		Deny: DenyConfig{Layers: []string{"adapters"}},
	})
	edges := []ImportEdge{
		{From: "example.com/app/internal/bootstrap", To: "example.com/app/internal/creator/adapters/postgres"},
	}

	violations := Check(cfg, edges)

	if len(violations) != 0 {
		t.Fatalf("Check() violations = %d; want 0", len(violations))
	}
}

func TestCheckIgnoresExternalImports(t *testing.T) {
	cfg := testConfig()
	edges := []ImportEdge{
		{From: "example.com/app/internal/creator/app", To: "go.uber.org/zap"},
	}

	violations := Check(cfg, edges)

	if len(violations) != 0 {
		t.Fatalf("Check() violations = %d; want 0", len(violations))
	}
}

func TestCheckUsesFromRelPathForTestPackages(t *testing.T) {
	cfg := testConfig()
	edges := []ImportEdge{
		{
			From:        "example.com/app/internal/creator/app_test",
			FromRelPath: "internal/creator/app",
			To:          "example.com/app/internal/market/adapters/postgres",
			Test:        true,
		},
	}

	violations := Check(cfg, edges)

	if len(violations) != 1 {
		t.Fatalf("Check() violations = %d; want 1", len(violations))
	}
	if violations[0].From != "internal/creator/app" {
		t.Fatalf("From = %q; want internal/creator/app", violations[0].From)
	}
}

func TestLoadImportGraphIncludesTestImportsWhenRequested(t *testing.T) {
	dir := writeBoundaryFixture(t)
	patterns := []string{"./internal/creator/app"}

	edges, err := LoadImportGraphWithOptions(dir, patterns, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadImportGraphWithOptions() error = %v", err)
	}
	if _, ok := importEdgeTo(edges, "example.com/app/internal/market/adapters/postgres"); ok {
		t.Fatalf("LoadImportGraphWithOptions() included test import without IncludeTests")
	}

	edges, err = LoadImportGraphWithOptions(dir, patterns, LoadOptions{IncludeTests: true})
	if err != nil {
		t.Fatalf("LoadImportGraphWithOptions(IncludeTests) error = %v", err)
	}
	edge, ok := importEdgeTo(edges, "example.com/app/internal/market/adapters/postgres")
	if !ok {
		t.Fatalf("LoadImportGraphWithOptions(IncludeTests) did not include test import")
	}
	if !edge.Test {
		t.Fatalf("test import edge Test = false; want true")
	}
	if edge.FromRelPath != "internal/creator/app" {
		t.Fatalf("test import edge FromRelPath = %q; want internal/creator/app", edge.FromRelPath)
	}
}

func importEdgeTo(edges []ImportEdge, to string) (ImportEdge, bool) {
	for _, edge := range edges {
		if edge.To == to {
			return edge, true
		}
	}
	return ImportEdge{}, false
}

func writeBoundaryFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/creator/app/app.go", "package app\n\nfunc Name() string { return \"creator\" }\n")
	writeTestFile(t, dir, "internal/creator/app/app_test.go", `package app_test

import (
	_ "example.com/app/internal/market/adapters/postgres"
	"testing"
)

func TestApp(t *testing.T) {}
`)
	writeTestFile(t, dir, "internal/market/adapters/postgres/postgres.go", "package postgres\n\nfunc Name() string { return \"postgres\" }\n")
	return dir
}

func writeTestFile(t *testing.T, dir, name, data string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("make test dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
}

func testConfig() Config {
	return Config{
		Packages: PackagesConfig{Root: "example.com/app"},
		Modules: []ModuleConfig{
			{Name: "creator", Path: "internal/creator"},
			{Name: "market", Path: "internal/market"},
		},
		Layers: []LayerConfig{
			{Name: "domain", Path: "domain"},
			{Name: "app", Path: "app"},
			{Name: "adapters", Path: "adapters"},
		},
		Rules: []RuleConfig{
			{
				Name: "app-no-foreign-adapters",
				From: Selector{Layer: "app"},
				Deny: DenyConfig{Layers: []string{"adapters"}, ExceptSameModule: true},
			},
		},
	}
}
