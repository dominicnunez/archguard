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

func TestCheckProfilesFindsProtocolTagsInDomain(t *testing.T) {
	dir := writeDomainProtocolTagFixture(t)
	cfg := externalTypeConfig()
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, ruleProtocolTagInDomain)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleProtocolTagInDomain, violations)
	}
	if !strings.Contains(violation.From, "internal/creator/domain/types.go") {
		t.Fatalf("From = %q; want domain file", violation.From)
	}
	if violation.To != "json" {
		t.Fatalf("To = %q; want json", violation.To)
	}
}

func TestCheckProfilesFindsAppInterfaceExternalTypes(t *testing.T) {
	dir := writeAppInterfaceExternalTypeFixture(t)
	cfg := externalTypeConfig()
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, ruleAppInterfaceExternalType)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleAppInterfaceExternalType, violations)
	}
	if violation.To != "example.com/sdk.ExternalID" {
		t.Fatalf("To = %q; want example.com/sdk.ExternalID", violation.To)
	}
}

func TestCheckProfilesFindsPrimitiveTimeFieldsInPorts(t *testing.T) {
	dir := writePrimitiveTimePortsFixture(t)
	cfg := externalTypeConfig()
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, rulePrimitiveTimeInPorts)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", rulePrimitiveTimeInPorts, violations)
	}
	if violation.To != "CoinDetails.LastTradeTimestamp" {
		t.Fatalf("To = %q; want CoinDetails.LastTradeTimestamp", violation.To)
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

func TestCheckProfilesIgnoresBroadPersistencePorts(t *testing.T) {
	dir := writeBroadPersistencePortsFixture(t)
	cfg := externalTypeConfig()
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}
	if _, ok := violationByRule(violations, ruleBroadPortsFile); ok {
		t.Fatalf("CheckLoadedPackages() reported broad persistence ports file: %v", violations)
	}
	if _, ok := violationByRule(violations, ruleBroadPortsInterface); ok {
		t.Fatalf("CheckLoadedPackages() reported broad persistence port interface: %v", violations)
	}
}

func TestCheckProfilesFindsThinAdapters(t *testing.T) {
	dir := writeThinAdapterFixture(t)
	cfg := externalTypeConfig()
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	embeddedViolation, ok := violationByRule(violations, ruleAdapterEmbedsForeignPort)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleAdapterEmbedsForeignPort, violations)
	}
	if embeddedViolation.To != "internal/token/ports.Repository" {
		t.Fatalf("embedded port To = %q; want internal/token/ports.Repository", embeddedViolation.To)
	}
	forwardingViolation, ok := violationByRule(violations, ruleThinAdapterForwarding)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleThinAdapterForwarding, violations)
	}
	if forwardingViolation.To != fmt.Sprint(minThinAdapterForwarders) {
		t.Fatalf("forwarding To = %q; want %d", forwardingViolation.To, minThinAdapterForwarders)
	}
}

func TestCheckProfilesFindsCompositionRootPatterns(t *testing.T) {
	dir := writeCompositionRootFixture(t)
	cfg := externalTypeConfig()
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	for _, rule := range []string{ruleCompositionMutation, ruleCompositionSetterCall, ruleCompositionDomainConvert} {
		if _, ok := violationByRule(violations, rule); !ok {
			t.Fatalf("CheckLoadedPackages() missing %s violation: %v", rule, violations)
		}
	}
}

func TestCheckProfilesFindsCrossModuleSQLTables(t *testing.T) {
	dir := writeSQLTableFixture(t)
	cfg := externalTypeConfig()
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, ruleSQLCrossModuleTable)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleSQLCrossModuleTable, violations)
	}
	if violation.To != "creator_stats (creator)" {
		t.Fatalf("SQL table To = %q; want creator_stats (creator)", violation.To)
	}
}

func TestCheckProfilesUsesConfiguredSQLTableOwners(t *testing.T) {
	dir := writeConfiguredSQLTableFixture(t)
	cfg := externalTypeConfig()
	cfg.Analysis.TableOwners = []TableOwnerConfig{{Module: "creator", Tables: []string{"wallets"}}}
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, ruleSQLCrossModuleTable)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleSQLCrossModuleTable, violations)
	}
	if violation.To != "wallets (creator)" {
		t.Fatalf("SQL table To = %q; want wallets (creator)", violation.To)
	}
}

func TestCheckProfilesFindsSQLTableOwnershipViolationsOutsideAdapters(t *testing.T) {
	dir := writeSQLFixtureReachthroughFixture(t)
	cfg := externalTypeConfig()
	cfg.Analysis.TableOwners = []TableOwnerConfig{{Module: "creator", Tables: []string{"wallets"}}}
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, ruleSQLCrossModuleTable)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleSQLCrossModuleTable, violations)
	}
	if violation.To != "wallets (creator)" {
		t.Fatalf("SQL table To = %q; want wallets (creator)", violation.To)
	}
}

func TestCheckProfilesFindsOwnedTableNameLiteralOutsideOwner(t *testing.T) {
	dir := writeTableNameLiteralFixture(t)
	cfg := externalTypeConfig()
	cfg.Analysis.TableOwners = []TableOwnerConfig{{Module: "creator", Tables: []string{"wallets"}}}
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, ruleSQLCrossModuleTable)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleSQLCrossModuleTable, violations)
	}
	if violation.To != "wallets (creator)" {
		t.Fatalf("SQL table To = %q; want wallets (creator)", violation.To)
	}
}

func TestCheckProfilesFindsExternalImportsOutsideAllowlist(t *testing.T) {
	dir := writeExternalImportAllowlistFixture(t)
	cfg := externalTypeConfig()
	cfg.Analysis.ExternalImports = []ExternalImportConfig{{
		Name: "app-external-imports",
		From: Selector{Layer: "app"},
		Allow: ExternalImportAllowConfig{Packages: []string{
			"example.com/logging",
		}},
	}}
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, ruleExternalImportNotAllowed)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleExternalImportNotAllowed, violations)
	}
	if violation.From != "internal/creator/app" || violation.To != "example.com/infra" {
		t.Fatalf("violation = %+v; want creator app importing example.com/infra", violation)
	}
}

func TestCheckProfilesFindsExternalImportsWithEmptyAllowlist(t *testing.T) {
	dir := writeExternalImportAllowlistFixture(t)
	cfg := externalTypeConfig()
	cfg.Analysis.ExternalImports = []ExternalImportConfig{{
		Name: "domain-external-imports",
		From: Selector{Layer: "app"},
	}}
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	var externalImportViolations []Violation
	for _, violation := range violations {
		if violation.Rule == ruleExternalImportNotAllowed {
			externalImportViolations = append(externalImportViolations, violation)
		}
	}
	if len(externalImportViolations) != 2 {
		t.Fatalf("external import violations = %v; want two", externalImportViolations)
	}
}

func TestCheckProfilesFindsPortsImportingAdapters(t *testing.T) {
	dir := writePortsAdapterImportFixture(t)
	cfg := externalTypeConfig()
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, rulePortsImportAdapter)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", rulePortsImportAdapter, violations)
	}
	if violation.From != "internal/creator/ports" || violation.To != "internal/creator/adapters/postgres" {
		t.Fatalf("violation = %+v; want ports importing postgres adapter", violation)
	}
}

func TestCheckProfilesFindsProtocolBoundaryInternalTypes(t *testing.T) {
	dir := writeProtocolBoundaryFixture(t)
	cfg := externalTypeConfig()
	cfg.Analysis.ProtocolBoundaries = []ProtocolBoundaryConfig{{
		Name:            "api-domain-protocol",
		From:            Selector{Path: "internal/api**"},
		Disallow:        TargetSelector{Layer: "domain"},
		ResponseSinks:   []string{"JSON", "respondWithList"},
		RequestDecoders: []string{"decodeJSONStrict"},
		Docs:            true,
	}, {
		Name:            "api-config-protocol",
		From:            Selector{Path: "internal/api**"},
		Disallow:        TargetSelector{Path: "internal/config"},
		ResponseSinks:   []string{"JSON", "respondWithList"},
		RequestDecoders: []string{"decodeJSONStrict"},
		Docs:            true,
	}}
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	for _, rule := range []string{ruleProtocolResponseType, ruleProtocolRequestType, ruleProtocolDocType} {
		if _, ok := violationByRule(violations, rule); !ok {
			t.Fatalf("CheckLoadedPackages() missing %s violation: %v", rule, violations)
		}
	}
}

func TestCheckProfilesFindsConfiguredProtocolTags(t *testing.T) {
	dir := writeConfiguredProtocolTagFixture(t)
	cfg := externalTypeConfig()
	cfg.Analysis.ProtocolTags = []ProtocolTagConfig{{
		Name: "runtime-json-tags",
		From: Selector{Path: "internal/config"},
	}}
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, ruleConfiguredProtocolTag)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleConfiguredProtocolTag, violations)
	}
	if !strings.Contains(violation.From, "internal/config/config.go") {
		t.Fatalf("From = %q; want config file", violation.From)
	}
}

func TestCheckProfilesFindsCrossModuleDependencyInjection(t *testing.T) {
	dir := writeDependencyInjectionFixture(t)
	cfg := externalTypeConfig()
	cfg.Modules = append(cfg.Modules, ModuleConfig{Name: "market", Path: "internal/market"})
	cfg.Analysis.DependencyInjections = []DependencyInjectionConfig{{
		Name:           "creator-market-injection",
		From:           Selector{Path: "internal/bootstrap"},
		Field:          "WalletRepo",
		ConsumerModule: "creator",
		Disallow:       TargetSelector{Module: "market"},
	}}
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, ruleDependencyInjection)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleDependencyInjection, violations)
	}
	if violation.To != "WalletRepo -> internal/market/adapters/postgres.WalletRepository" {
		t.Fatalf("To = %q; want market wallet repository injection", violation.To)
	}
}

func TestCheckProfilesFindsForbiddenBoundaryTerms(t *testing.T) {
	dir := writeForbiddenBoundaryTermFixture(t)
	cfg := externalTypeConfig()
	cfg.Analysis.ForbiddenTerms = []ForbiddenTermConfig{{
		Name:  "vendor terms in ports",
		From:  Selector{Path: "internal/token/ports"},
		Terms: []string{"pump", "v3coin"},
	}, {
		Name:  "vendor terms in domain",
		From:  Selector{Path: "internal/token/domain"},
		Terms: []string{"dexscreener"},
	}}
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	if _, ok := violationByRule(violations, ruleForbiddenBoundaryTerm); !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleForbiddenBoundaryTerm, violations)
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

func writeExternalImportAllowlistFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", `module example.com/app

go 1.23

require example.com/infra v0.0.0
require example.com/logging v0.0.0

replace example.com/infra => ./infra
replace example.com/logging => ./logging
`)
	writeTestFile(t, dir, "infra/go.mod", "module example.com/infra\n\ngo 1.23\n")
	writeTestFile(t, dir, "infra/infra.go", "package infra\n\nfunc Use() {}\n")
	writeTestFile(t, dir, "logging/go.mod", "module example.com/logging\n\ngo 1.23\n")
	writeTestFile(t, dir, "logging/logging.go", "package logging\n\nfunc Use() {}\n")
	writeTestFile(t, dir, "internal/creator/app/app.go", `package app

import (
	"example.com/infra"
	"example.com/logging"
)

func Run() {
	infra.Use()
	logging.Use()
}
`)
	return dir
}

func writePortsAdapterImportFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/creator/adapters/postgres/repo.go", "package postgres\n\ntype Repository struct{}\n")
	writeTestFile(t, dir, "internal/creator/ports/ports.go", `package ports

import creatorpostgres "example.com/app/internal/creator/adapters/postgres"

var _ = (*creatorpostgres.Repository)(nil)
	`)
	return dir
}

func writeProtocolBoundaryFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/creator/domain/types.go", `package domain

type CreatorStats struct {
	Wallet string
}
`)
	writeTestFile(t, dir, "internal/config/config.go", `package config

type ThorConfig struct {
	Enabled bool `+"`json:\"enabled\"`"+`
}

func DefaultConfig() *ThorConfig { return &ThorConfig{} }
`)
	writeTestFile(t, dir, "internal/api/handlers/handler.go", `package handlers

import (
	"net/http"

	"example.com/app/internal/config"
	"example.com/app/internal/creator/domain"
)

type context struct{}

func (c *context) JSON(int, any) {}

func respondWithList(c *context, key string, data any, total int, meta any) {}

func decodeJSONStrict(c *context, out any) error { return nil }

// Get godoc
// @Success 200 {object} domain.CreatorStats
// @Success 200 {object} config.ThorConfig
func Get(c *context, stats []domain.CreatorStats) {
	respondWithList(c, "creators", stats, len(stats), nil)
	cfg := config.DefaultConfig()
	c.JSON(http.StatusOK, map[string]any{"config": cfg})
	var updates config.ThorConfig
	_ = decodeJSONStrict(c, &updates)
}
`)
	return dir
}

func writeConfiguredProtocolTagFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/config/config.go", `package config

type ThorConfig struct {
	Enabled bool `+"`json:\"enabled\"`"+`
}
`)
	writeTestFile(t, dir, "internal/api/handlers/dto.go", `package handlers

type Response struct {
	Enabled bool `+"`json:\"enabled\"`"+`
}
`)
	return dir
}

func writeDependencyInjectionFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/market/adapters/postgres/wallet.go", `package postgres

type WalletRepository struct{}
`)
	writeTestFile(t, dir, "internal/creator/app/service.go", `package app

type CreatorDeps struct {
	WalletRepo any
}

type Service struct{}

func NewService(CreatorDeps) *Service { return &Service{} }
`)
	writeTestFile(t, dir, "internal/bootstrap/bootstrap.go", `package bootstrap

import (
	creator "example.com/app/internal/creator/app"
	marketpostgres "example.com/app/internal/market/adapters/postgres"
)

func Build() *creator.Service {
	marketRepo := &marketpostgres.WalletRepository{}
	return creator.NewService(creator.CreatorDeps{WalletRepo: marketRepo})
}
`)
	return dir
}

func writeForbiddenBoundaryTermFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/token/ports/ports.go", `package ports

// PumpAPI is a pump.fun-shaped port.
type PumpAPI interface {
	GetCoinDetails() (*V3CoinResponse, error)
}

type V3CoinResponse struct{}
`)
	writeTestFile(t, dir, "internal/token/domain/types.go", `package domain

const SourceDexScreener = "dexscreener"
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

func writeDomainProtocolTagFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/creator/domain/types.go", `package domain

type CreatorStats struct {
	WalletAddress string `+"`json:\"wallet_address\"`"+`
}
`)
	writeTestFile(t, dir, "internal/creator/app/app.go", `package app

type CreatorResponse struct {
	WalletAddress string `+"`json:\"wallet_address\"`"+`
}
`)
	return dir
}

func writeAppInterfaceExternalTypeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", `module example.com/app

go 1.23

require example.com/sdk v0.0.0

replace example.com/sdk => ./sdk
`)
	writeTestFile(t, dir, "sdk/go.mod", "module example.com/sdk\n\ngo 1.23\n")
	writeTestFile(t, dir, "sdk/sdk.go", "package sdk\n\ntype ExternalID string\n")
	writeTestFile(t, dir, "internal/creator/app/app.go", `package app

import (
	"context"

	"example.com/sdk"
)

type Provider interface {
	Lookup(context.Context, sdk.ExternalID) error
}
`)
	return dir
}

func writePrimitiveTimePortsFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/creator/ports/ports.go", `package ports

type CoinDetails struct {
	LastTradeTimestamp *int64
	Name               string
}
`)
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

func writeBroadPersistencePortsFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")

	var ports strings.Builder
	ports.WriteString("package ports\n\n")
	for i := 0; i < maxPortsInterfacesPerFile+1; i++ {
		fmt.Fprintf(&ports, "type Store%dRepository interface {\n", i)
		for j := 0; j < maxPortsInterfaceMethods+1; j++ {
			fmt.Fprintf(&ports, "\tMethod%d()\n", j)
		}
		ports.WriteString("}\n\n")
	}
	writeTestFile(t, dir, "internal/creator/ports/repositories.go", ports.String())
	return dir
}

func writeThinAdapterFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/token/ports/ports.go", `package ports

import "context"

type Repository interface {
	Count(ctx context.Context, wallet string) (int, error)
	CountBatch(ctx context.Context, wallets []string) (map[string]int, error)
}
`)
	writeTestFile(t, dir, "internal/creator/adapters/token/source.go", `package token

import (
	"context"

	tokenports "example.com/app/internal/token/ports"
)

type Source struct {
	repo sourceRepository
}

type sourceRepository interface {
	tokenports.Repository
}

func (s *Source) Count(ctx context.Context, wallet string) (int, error) {
	return s.repo.Count(ctx, wallet)
}

func (s *Source) CountBatch(ctx context.Context, wallets []string) (map[string]int, error) {
	return s.repo.CountBatch(ctx, wallets)
}
`)
	return dir
}

func writeCompositionRootFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/token/domain/domain.go", "package domain\n\ntype Venue string\n")
	writeTestFile(t, dir, "internal/token/app/service.go", `package app

type Service struct {
	notifier any
}

func (s *Service) SetNotifier(notifier any) {
	s.notifier = notifier
}
`)
	writeTestFile(t, dir, "internal/bootstrap/bootstrap.go", `package bootstrap

import (
	tokenapp "example.com/app/internal/token/app"
	tokendomain "example.com/app/internal/token/domain"
)

type Server struct {
	limiter any
}

func RegisterRoutes(server *Server) {
	server.limiter = struct{}{}
}

func Build(service *tokenapp.Service, raw string) {
	service.SetNotifier(struct{}{})
	_ = tokendomain.Venue(raw)
}
`)
	return dir
}

func writeSQLTableFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/token/adapters/postgres/repo.go", `package postgres

const localQuery = "SELECT * FROM tokens"
const foreignQuery = "SELECT * FROM creator_stats WHERE wallet_address = $1"
`)
	return dir
}

func writeConfiguredSQLTableFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/token/adapters/postgres/repo.go", `package postgres

const query = "TRUNCATE wallets CASCADE"
`)
	return dir
}

func writeSQLFixtureReachthroughFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/testhelpers/testdb.go", `package testhelpers

import "database/sql"

func EnsureWallet(db *sql.DB) {
	_ = db
	_ = "INSERT INTO wallets (address) VALUES ($1)"
}
`)
	return dir
}

func writeTableNameLiteralFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeTestFile(t, dir, "internal/token/adapters/postgres/repo.go", `package postgres

import "database/sql"

func Truncate(db *sql.DB) {
	_ = db
	TruncateTable("wallets")
}

func TruncateTable(_ string) {}
`)
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
			{Name: "token", Path: "internal/token"},
		},
		Layers: []LayerConfig{
			{Name: "domain", Path: "domain"},
			{Name: "app", Path: "app"},
			{Name: portsLayerName, Path: portsLayerName},
			{Name: adaptersLayerName, Path: adaptersLayerName},
		},
		Analysis: AnalysisConfig{Profiles: []string{profileModularMonolith}},
	}
}
