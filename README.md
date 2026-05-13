# gomodguard

`gomodguard` checks Go modular-monolith import boundaries from a project-local config file.

It is intentionally configuration-driven: the tool knows how to load a Go import graph and evaluate rules, while each repository defines its own modules, layers, exceptions, and migration allowlist.

## Usage

```bash
gomodguard check
gomodguard check --config .gomodguard.yaml
gomodguard check --dir /path/to/repo --config /path/to/repo/.gomodguard.yaml
```

By default, `gomodguard check` looks for one of:

- `gomodguard.yaml`
- `gomodguard.yml`
- `gomodguard.json`
- `.gomodguard.yaml`
- `.gomodguard.yml`
- `.gomodguard.json`

## Config

See `examples/thor.gomodguard.yaml` for a real modular-monolith config.

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
  - name: adapters
    path: adapters

rules:
  - name: domain-no-foreign-modules
    from:
      layer: domain
    deny:
      modules: ["*"]
      except_same_module: true

  - name: app-no-foreign-adapters
    from:
      layer: app
    deny:
      layers: [adapters]
      except_same_module: true

allow:
  - from: internal/bootstrap
    to: internal/*/adapters/postgres
    reason: composition root wires concrete repositories
```

## Rule Model

- `modules` identify bounded contexts by repository-relative path.
- `layers` identify conventional subdirectories within modules.
- `rules` select importers with `from`, then deny imports by target module, layer, or path.
- `allow` entries are explicit exceptions for known migration seams.

Path patterns support `*`, `?`, and `**`.
