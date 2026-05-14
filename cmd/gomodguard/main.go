package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dominicnunez/gomodguard/internal/guard"
)

type stringListFlag []string

func (f *stringListFlag) String() string { return strings.Join(*f, ",") }

func (f *stringListFlag) Set(value string) error {
	if value == "" {
		return nil
	}
	*f = append(*f, value)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, guard.ErrViolationsFound) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "gomodguard: %v\n", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return nil
	}

	switch args[0] {
	case "check":
		return runCheck(args[1:])
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "path to .gomodguard.yaml, .gomodguard.yml, or .gomodguard.json")
	dir := fs.String("dir", ".", "repository directory to analyze")
	includeTests := fs.Bool("include-tests", false, "include Go test variants in import and analysis checks")
	var cliProfiles stringListFlag
	fs.Var(&cliProfiles, "profile", "enable a built-in analysis profile; may be repeated")
	if err := fs.Parse(args); err != nil {
		return err
	}

	repoDir, err := filepath.Abs(*dir)
	if err != nil {
		return fmt.Errorf("resolve repo dir: %w", err)
	}

	resolvedConfig := *configPath
	if resolvedConfig == "" {
		resolvedConfig, err = guard.FindConfig(repoDir)
		if err != nil {
			return err
		}
	} else if !filepath.IsAbs(resolvedConfig) {
		resolvedConfig = filepath.Join(repoDir, resolvedConfig)
	}

	cfg, err := guard.LoadConfig(resolvedConfig)
	if err != nil {
		return err
	}
	if *includeTests {
		cfg.Analysis.IncludeTests = true
	}
	if len(cliProfiles) > 0 {
		cfg.Analysis.Profiles = append(cfg.Analysis.Profiles, cliProfiles...)
	}
	patterns := fs.Args()
	if len(patterns) == 0 {
		patterns = cfg.PackagePatterns()
	}

	pkgs, err := guard.LoadPackages(repoDir, patterns, guard.LoadOptions{
		IncludeTests: cfg.Analysis.IncludeTests,
		NeedSyntax:   guard.AnalysisRequiresSyntax(cfg),
	})
	if err != nil {
		return err
	}
	violations, err := guard.CheckLoadedPackages(cfg, pkgs)
	if err != nil {
		return err
	}
	if len(violations) == 0 {
		fmt.Fprintln(os.Stdout, "gomodguard: no boundary violations")
		return nil
	}

	printViolations(os.Stdout, violations)
	return guard.ErrViolationsFound
}

func printViolations(out *os.File, violations []guard.Violation) {
	fmt.Fprintf(out, "gomodguard: %d boundary violation(s)\n", len(violations))
	for _, violation := range violations {
		fmt.Fprintf(out, "\n%s\n", violation.Rule)
		fmt.Fprintf(out, "  from: %s\n", violation.From)
		fmt.Fprintf(out, "  to:   %s\n", violation.To)
		fmt.Fprintf(out, "  why:  %s\n", violation.Message)
	}
}

func printUsage(out *os.File) {
	usage := strings.TrimSpace(`gomodguard checks Go modular-monolith import boundaries.

Usage:
  gomodguard check [--config .gomodguard.yaml] [--dir .] [--include-tests] [--profile name] [patterns...]
  gomodguard help`)
	fmt.Fprintln(out, usage)
}
