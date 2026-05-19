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

## Config

See `examples/thor.archguard.yaml` for a real modular-monolith config.
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
```

Optional analysis profiles enable generic AST/SQL checks without adding
project-specific import rules:

```yaml
analysis:
  include_tests: true
  profiles:
    - modular-monolith
```

## Rule Model

- `modules` identify bounded contexts by repository-relative path.
- `layers` identify conventional subdirectories within modules.
- `policy.default` must be `deny`; internal imports are rejected unless an allow rule matches.
- `policy.allow` entries select importers with `from`, then allow target imports with `to`.
- `from.tests: true` restricts an allow rule to test import edges; `from.tests: false` restricts it to production import edges.
- `to.same_module` allows imports only when source and target are in the same configured module.
- `to.internal` allows imports to any internal package.
- `to.module`, `to.modules`, `to.layer`, `to.layers`, `to.path`, and `to.paths` narrow allowed targets.
- `ignore` entries exclude known generated or out-of-scope paths from import checks.
- `analysis.include_tests` includes Go test variants in import checks and profile checks.
- `analysis.profiles` enables reusable built-in checks such as `modular-monolith`.
- `modular-monolith` reports exported `ports` APIs that reference non-stdlib external dependency types.
- `modular-monolith` reports exported `ports` structs with protocol field tags such as `json`.
- `modular-monolith` reports broad `ports` files and interfaces with large method surfaces.
- `modular-monolith` reports thin adapters that embed foreign ports or only forward calls.
- `modular-monolith` reports composition-root mutation, Set-style wiring, domain conversions, and cross-module SQL table references.

Path patterns support `*`, `?`, and `**`.
