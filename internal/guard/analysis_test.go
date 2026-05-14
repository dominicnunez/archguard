package guard

import (
	"fmt"
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

func TestCheckProfilesFindsProtocolDTOsInPorts(t *testing.T) {
	dir := writeProtocolDTOFixture(t)
	cfg := externalTypeConfig()
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, ruleProtocolDTOInPorts)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleProtocolDTOInPorts, violations)
	}
	if !strings.Contains(violation.From, "internal/creator/ports/ports.go") {
		t.Fatalf("From = %q; want ports file", violation.From)
	}
	if violation.To != "json" {
		t.Fatalf("To = %q; want json", violation.To)
	}
	if strings.Contains(violation.Message, "AppResponse") {
		t.Fatalf("Message = %q; app-layer DTO should not be flagged", violation.Message)
	}
}

func TestCheckProfilesFindsBroadPortsSurfaces(t *testing.T) {
	dir := writeBroadPortsFixture(t)
	cfg := externalTypeConfig()
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	fileViolation, ok := violationByRule(violations, ruleBroadPortsFile)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleBroadPortsFile, violations)
	}
	if fileViolation.To != fmt.Sprint(maxPortsInterfacesPerFile+1) {
		t.Fatalf("broad file To = %q; want %d", fileViolation.To, maxPortsInterfacesPerFile+1)
	}
	interfaceViolation, ok := violationByRule(violations, ruleBroadPortsInterface)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleBroadPortsInterface, violations)
	}
	if interfaceViolation.To != fmt.Sprint(maxPortsInterfaceMethods+1) {
		t.Fatalf("broad interface To = %q; want %d", interfaceViolation.To, maxPortsInterfaceMethods+1)
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

func writeProtocolDTOFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/creator/ports/ports.go", "package ports\n\ntype HTTPResponse struct {\n\tID      string `json:\"id\"`\n\tIgnored string `json:\"-\"`\n}\n")
	writeTestFile(t, dir, "internal/creator/app/app.go", "package app\n\ntype AppResponse struct {\n\tID string `json:\"id\"`\n}\n")
	return dir
}

func writeBroadPortsFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")

	var ports strings.Builder
	ports.WriteString("package ports\n\n")
	for i := 0; i < maxPortsInterfacesPerFile+1; i++ {
		fmt.Fprintf(&ports, "type Port%d interface {\n\tMethod%d()\n}\n\n", i, i)
	}
	writeTestFile(t, dir, "internal/creator/ports/ports.go", ports.String())

	var wide strings.Builder
	wide.WriteString("package ports\n\ntype Wide interface {\n")
	for i := 0; i < maxPortsInterfaceMethods+1; i++ {
		fmt.Fprintf(&wide, "\tMethod%d()\n", i)
	}
	wide.WriteString("}\n")
	writeTestFile(t, dir, "internal/creator/ports/wide.go", wide.String())
	return dir
}

func violationByRule(violations []Violation, rule string) (Violation, bool) {
	for _, violation := range violations {
		if violation.Rule == rule {
			return violation, true
		}
	}
	return Violation{}, false
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
