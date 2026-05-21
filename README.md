# archguard

`archguard` checks Go modular-monolith import boundaries from a project-local config file.

It is intentionally configuration-driven: the tool knows how to load a Go import graph and evaluate a default-deny import policy, while each repository defines its own modules, layers, and allowed boundary crossings.

## Usage

```bash
archguard check
archguard check --config .archguard.yaml
archguard check --dir /path/to/repo --config /path/to/repo/.archguard.yaml
archguard check --config .archguard.jsonc
archguard check --include-tests --profile modular-monolith
```

By default, `archguard check` looks for one of:

- `archguard.yaml`
- `archguard.yml`
- `archguard.jsonc`
- `.archguard.yaml`
- `.archguard.yml`
- `.archguard.jsonc`

Legacy `gomodguard.*` config names are not discovered; rename project configs to
one of the `archguard.*` names above.

## Config

JSONC config files support comments and trailing commas.

```yaml
version: 1

packages:
  root: github.com/example/app
  patterns:
    - ./internal/...

modules:
  - name: orders
    path: internal/orders
  - name: billing
    path: internal/billing

layers:
  - name: domain
    path: domain
  - name: app
    path: app
  - name: ports
    path: ports
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

  - name: app-to-local-domain-and-ports
    from:
      layer: app
    to:
      same_module: true
      layers: [domain, ports]

  - name: bootstrap-wiring
    from:
      path: internal/bootstrap/**
    to:
      internal: true

  - name: app-test-support
    from:
      layer: app
      tests: true
    to:
      paths:
        - internal/testhelpers
```

Optional analysis profiles enable generic AST/SQL checks without adding
project-specific import rules:

```yaml
analysis:
  include_tests: true
  profiles:
    - modular-monolith
  table_owners:
    - module: market
      tables: [wallets, wallet_clusters]
  sql_table_references:
    - name: migration-single-owner-statements
      path: migrations/*.sql
      ignore_paths:
        - migrations/001_legacy_schema.sql
      max_owners_per_statement: 1
  external_imports:
    - name: domain-production-imports
      from:
        layer: domain
        tests: false
    - name: app-production-imports
      from:
        layer: app
        tests: false
      allow:
        packages:
          - go.uber.org/zap
          - github.com/google/uuid
  protocol_boundaries:
    - name: api-domain-responses
      from:
        path: internal/api/handlers
      disallow:
        layer: domain
      response_sinks: [JSON, respondWithList]
      request_decoders: [ShouldBindJSON]
      docs: true
  protocol_tags:
    - name: runtime-json-tags
      from:
        path: internal/workers
  dependency_injections:
    - name: orders-foreign-store-injection
      from:
        path: internal/bootstrap**
      field: WalletStore
      consumer_module: orders
      disallow:
        module: accounts
  forbidden_terms:
    - name: vendor-terms-in-ports
      from:
        layer: ports
      terms: [stripe, github]
```

## Rule Model

- `modules` identify bounded contexts by repository-relative path.
- `layers` identify conventional subdirectories within modules.
- `policy.default` must be `deny`; internal imports are rejected unless an allow rule matches.
- `policy.allow` entries select importers with `from`, then allow target imports with `to`.
- `from.tests: true` restricts an allow rule to test import edges; `from.tests: false` restricts it to production import edges; omitting `tests` preserves the default behavior and matches both.
- `to.same_module` allows imports only when source and target are in the same configured module.
- `to.internal` allows imports to any internal package.
- `to.module`, `to.modules`, `to.layer`, `to.layers`, `to.path`, and `to.paths` narrow allowed targets.
- `ignore` entries exclude known generated or out-of-scope paths from import checks.
- `analysis.include_tests` includes Go test variants in import checks and profile checks.
- `analysis.profiles` enables reusable built-in checks such as `modular-monolith`.
- `analysis.table_owners` maps table names or wildcard patterns to owning modules for SQL ownership checks when table names do not follow module-name conventions.
- `analysis.sql_table_references` scans configured SQL files and reports references to disallowed table owners or statements that touch more table-owner modules than `max_owners_per_statement`; `ignore_paths` can baseline historical SQL files while keeping the rule active for future files.
- `analysis.external_imports` defines an allowlist for external imports from selected packages; matching packages reject external imports not listed in `allow`, and omitted `allow` means no external imports are allowed.
- `analysis.protocol_boundaries` defines transport sink/decoder/doc checks that reject configured internal types at protocol boundaries.
- `analysis.protocol_tags` reports protocol field tags in selected packages outside transport-owned DTOs.
- `analysis.dependency_injections` reports configured composition-root field injections that pass dependencies from disallowed modules into another module's dependency struct.
- `analysis.forbidden_terms` reports configured vendor/protocol terms in selected packages; when `identifiers`, `strings`, and `comments` are all omitted, all three are checked.
- `modular-monolith` reports exported `ports` APIs that reference non-stdlib external dependency types.
- `modular-monolith` reports `ports` packages that import adapter implementations.
- `modular-monolith` applies configured protocol boundary, protocol tag, dependency injection, and forbidden term checks.
- `modular-monolith` reports exported `domain` structs with protocol field tags such as `json`.
- `modular-monolith` reports exported `app` interfaces that expose non-stdlib external dependency types.
- `modular-monolith` reports exported `ports` structs with protocol field tags such as `json`.
- `modular-monolith` reports exported `ports` structs that expose primitive numeric time fields such as integer timestamps.
- `modular-monolith` reports broad `ports` files and non-persistence interfaces with large method surfaces. Persistence-shaped ports ending in `Repository` or `DataSource` are excluded from this broad-surface heuristic.
- `modular-monolith` reports thin adapters that embed foreign ports or only forward calls, including cross-module local-interface wrappers.
- `modular-monolith` reports composition-root mutation, Set-style wiring, domain conversions, and SQL table references from non-owning DB-access packages or configured SQL files.

Path patterns support `*`, `?`, and `**`.
