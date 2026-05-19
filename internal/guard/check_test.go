package guard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDeniesUnmatchedInternalImport(t *testing.T) {
	cfg := testConfig()
	edges := []ImportEdge{
		{From: "example.com/app/internal/creator/app", To: "example.com/app/internal/market/adapters/postgres"},
	}

	violations := Check(cfg, edges)

	if len(violations) != 1 {
		t.Fatalf("Check() violations = %d; want 1", len(violations))
	}
	if violations[0].Rule != rulePolicyDeny {
		t.Fatalf("Rule = %q; want %s", violations[0].Rule, rulePolicyDeny)
	}
}

func TestCheckAllowsSameModuleImport(t *testing.T) {
	cfg := testConfig()
	edges := []ImportEdge{
		{From: "example.com/app/internal/creator/app", To: "example.com/app/internal/creator/adapters/token"},
	}

	violations := Check(cfg, edges)

	if len(violations) != 0 {
		t.Fatalf("Check() violations = %d; want 0", len(violations))
	}
}

func TestCheckAllowsPathToInternal(t *testing.T) {
	cfg := testConfig()
	cfg.Policy.Allow = append(cfg.Policy.Allow, PolicyAllowConfig{Name: "bootstrap", From: Selector{Path: "internal/bootstrap"}, To: TargetSelector{Internal: true}})
	edges := []ImportEdge{
		{From: "example.com/app/internal/bootstrap", To: "example.com/app/internal/creator/adapters/postgres"},
	}

	violations := Check(cfg, edges)

	if len(violations) != 0 {
		t.Fatalf("Check() violations = %d; want 0", len(violations))
	}
}

func TestCheckAllowsTargetLayerWithinSameModule(t *testing.T) {
	cfg := testConfig()
	cfg.Policy.Allow = []PolicyAllowConfig{
		{Name: "app-to-domain", From: Selector{Layer: "app"}, To: TargetSelector{SameModule: true, Layers: []string{"domain"}}},
	}
	edges := []ImportEdge{
		{From: "example.com/app/internal/creator/app", To: "example.com/app/internal/creator/domain"},
		{From: "example.com/app/internal/creator/app", To: "example.com/app/internal/creator/adapters/token"},
	}

	violations := Check(cfg, edges)

	if len(violations) != 1 {
		t.Fatalf("Check() violations = %d; want 1", len(violations))
	}
	if violations[0].To != "internal/creator/adapters/token" {
		t.Fatalf("To = %q; want internal/creator/adapters/token", violations[0].To)
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
	if violations[0].Rule != rulePolicyDeny {
		t.Fatalf("Rule = %q; want %s", violations[0].Rule, rulePolicyDeny)
	}
	if violations[0].From != "internal/creator/app" {
		t.Fatalf("From = %q; want internal/creator/app", violations[0].From)
	}
}

func TestCheckAllowsTestOnlySelectorForTestImports(t *testing.T) {
	testsOnly := true
	cfg := testConfig()
	cfg.Policy.Allow = append(cfg.Policy.Allow, PolicyAllowConfig{
		Name: "creator-test-support",
		From: Selector{Path: "internal/creator/app", Tests: &testsOnly},
		To:   TargetSelector{Path: "internal/market/adapters/postgres"},
	})
	edges := []ImportEdge{
		{
			From:        "example.com/app/internal/creator/app_test",
			FromRelPath: "internal/creator/app",
			To:          "example.com/app/internal/market/adapters/postgres",
			Test:        true,
		},
		{
			From: "example.com/app/internal/creator/app",
			To:   "example.com/app/internal/market/adapters/postgres",
		},
	}

	violations := Check(cfg, edges)

	if len(violations) != 1 {
		t.Fatalf("Check() violations = %d; want 1", len(violations))
	}
	if violations[0].From != "internal/creator/app" || violations[0].To != "internal/market/adapters/postgres" {
		t.Fatalf("violation = %+v; want production edge only", violations[0])
	}
}

func TestCheckAllowsProductionOnlySelectorForProductionImports(t *testing.T) {
	productionOnly := false
	cfg := testConfig()
	cfg.Policy.Allow = append(cfg.Policy.Allow, PolicyAllowConfig{
		Name: "creator-production-support",
		From: Selector{Path: "internal/creator/app", Tests: &productionOnly},
		To:   TargetSelector{Path: "internal/market/adapters/postgres"},
	})
	edges := []ImportEdge{
		{
			From: "example.com/app/internal/creator/app",
			To:   "example.com/app/internal/market/adapters/postgres",
		},
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
	if violations[0].From != "internal/creator/app" || violations[0].To != "internal/market/adapters/postgres" {
		t.Fatalf("violation = %+v; want test edge only", violations[0])
	}
}

func TestCheckIgnoresConfiguredPaths(t *testing.T) {
	cfg := testConfig()
	cfg.Ignore = []IgnoreConfig{{Path: "internal/creator/app", Reason: "generated"}}
	edges := []ImportEdge{{From: "example.com/app/internal/creator/app", To: "example.com/app/internal/market/adapters/postgres"}}

	violations := Check(cfg, edges)

	if len(violations) != 0 {
		t.Fatalf("Check() violations = %d; want 0", len(violations))
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
		Policy: PolicyConfig{Default: "deny", Allow: []PolicyAllowConfig{
			{
				Name: "same-module",
				From: Selector{Module: "*"},
				To:   TargetSelector{SameModule: true},
			},
		}},
	}
}
