package guard

import "testing"

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
