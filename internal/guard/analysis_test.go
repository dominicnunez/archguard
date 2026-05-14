package guard

import (
	"strings"
	"testing"
)

func TestCheckProfilesFindsExternalTypesInExportedPortsAPI(t *testing.T) {
	dir := writeExternalTypeFixture(t)
	cfg := externalTypeConfig()
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	if len(violations) != 1 {
		t.Fatalf("CheckLoadedPackages() violations = %d; want 1", len(violations))
	}
	if violations[0].Rule != ruleExportedAPIExternalType {
		t.Fatalf("Rule = %q; want %s", violations[0].Rule, ruleExportedAPIExternalType)
	}
	if !strings.Contains(violations[0].From, "internal/creator/ports/ports.go") {
		t.Fatalf("From = %q; want ports file", violations[0].From)
	}
	if violations[0].To != "example.com/sdk.External" {
		t.Fatalf("To = %q; want example.com/sdk.External", violations[0].To)
	}
}

func TestCheckProfilesRejectsUnknownProfile(t *testing.T) {
	cfg := externalTypeConfig()
	cfg.Analysis.Profiles = []string{"missing"}

	_, err := CheckProfiles(cfg, nil)

	if err == nil || !strings.Contains(err.Error(), `unknown analysis profile "missing"`) {
		t.Fatalf("CheckProfiles() error = %v; want unknown profile error", err)
	}
}

func writeExternalTypeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", `module example.com/app

go 1.23

require example.com/sdk v0.0.0

replace example.com/sdk => ./sdk
`)
	writeTestFile(t, dir, "sdk/go.mod", "module example.com/sdk\n\ngo 1.23\n")
	writeTestFile(t, dir, "sdk/sdk.go", "package sdk\n\ntype External struct{}\n")
	writeTestFile(t, dir, "internal/creator/ports/ports.go", `package ports

import (
	"time"

	"example.com/sdk"
)

type Repository interface {
	Save(sdk.External, time.Time) error
}
`)
	writeTestFile(t, dir, "internal/creator/app/app.go", `package app

import "example.com/sdk"

func Build() sdk.External { return sdk.External{} }
`)
	return dir
}

func externalTypeConfig() Config {
	return Config{
		Packages: PackagesConfig{Root: "example.com/app"},
		Modules: []ModuleConfig{
			{Name: "creator", Path: "internal/creator"},
		},
		Layers: []LayerConfig{
			{Name: "app", Path: "app"},
			{Name: portsLayerName, Path: portsLayerName},
		},
		Analysis: AnalysisConfig{Profiles: []string{profileModularMonolith}},
	}
}
