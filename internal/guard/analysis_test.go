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

func TestCheckProfilesFindsForbiddenImports(t *testing.T) {
	dir := writeForbiddenImportFixture(t)
	cfg := externalTypeConfig()
	cfg.Analysis.ForbiddenImports = []ForbiddenImportConfig{{
		Name:    "app-infra",
		From:    Selector{Layer: "app"},
		Package: "example.com/infra",
		Reason:  "app packages must not import infrastructure packages",
	}}
	pkgs, err := LoadPackages(dir, []string{"./internal/..."}, LoadOptions{NeedSyntax: true})
	if err != nil {
		t.Fatalf("LoadPackages() error = %v", err)
	}

	violations, err := CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		t.Fatalf("CheckLoadedPackages() error = %v", err)
	}

	violation, ok := violationByRule(violations, ruleForbiddenImport)
	if !ok {
		t.Fatalf("CheckLoadedPackages() missing %s violation: %v", ruleForbiddenImport, violations)
	}
	if violation.From != "internal/creator/app" || violation.To != "example.com/infra" {
		t.Fatalf("violation = %+v; want creator app importing example.com/infra", violation)
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

func writeForbiddenImportFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "go.mod", `module example.com/app

go 1.23

require example.com/infra v0.0.0

replace example.com/infra => ./infra
`)
	writeTestFile(t, dir, "infra/go.mod", "module example.com/infra\n\ngo 1.23\n")
	writeTestFile(t, dir, "infra/infra.go", "package infra\n\nfunc Use() {}\n")
	writeTestFile(t, dir, "internal/creator/app/app.go", `package app

import "example.com/infra"

func Run() { infra.Use() }
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
