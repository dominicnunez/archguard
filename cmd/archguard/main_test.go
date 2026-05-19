package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dominicnunez/archguard/internal/guard"
)

func TestRunCheckIncludeTestsFlag(t *testing.T) {
	dir := writeCLIFixture(t)

	if err := run([]string{"check", "--dir", dir}); err != nil {
		t.Fatalf("run(check) error = %v; want nil", err)
	}

	err := run([]string{"check", "--dir", dir, "--include-tests"})
	if !errors.Is(err, guard.ErrViolationsFound) {
		t.Fatalf("run(check --include-tests) error = %v; want ErrViolationsFound", err)
	}
}

func writeCLIFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeCLIFile(t, dir, "go.mod", "module example.com/app\n\ngo 1.23\n")
	writeCLIFile(t, dir, "archguard.yml", `version: 1
packages:
  root: example.com/app
modules:
  - name: creator
    path: internal/creator
  - name: market
    path: internal/market
layers:
  - name: app
    path: app
  - name: adapters
    path: adapters
policy:
  default: deny
  allow:
  - name: same-module
    from:
      module: "*"
    to:
      same_module: true
`)
	writeCLIFile(t, dir, "internal/creator/app/app.go", "package app\n\nfunc Name() string { return \"creator\" }\n")
	writeCLIFile(t, dir, "internal/creator/app/app_test.go", `package app_test

import (
	_ "example.com/app/internal/market/adapters/postgres"
	"testing"
)

func TestApp(t *testing.T) {}
`)
	writeCLIFile(t, dir, "internal/market/adapters/postgres/postgres.go", "package postgres\n\nfunc Name() string { return \"postgres\" }\n")
	return dir
}

func writeCLIFile(t *testing.T, dir, name, data string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("make test dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
}
