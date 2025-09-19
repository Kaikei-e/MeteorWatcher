# Repository Guidelines

## Project Structure & Modules
- `src/`: Gleam source. Key areas: `collectors/` (OSV fetch/decode), `file_manager/` (CSV/IO), `index_searcher/` (index + scanning), `library_scanner/`, `vuln_extractors/`, `datastore/`, `utils/`.
- `test/`: Gleeunit tests by feature (e.g., `test/index_searcher/`, `*_test.gleam`).
- `build/`: Gleam build artifacts.
- Config/data: `targets.json` (scan roots), `osv_vulnerabilities/` (CSV/cache), `compose.yaml` (Postgres), SQL in `db/init/`.

## Build, Test, Run
- `gleam deps download`: Install dependencies.
- `gleam build`: Compile the project.
- `gleam test`: Run unit tests.
- `gleam run`: Execute `src/meteor_watcher.gleam` (reads `targets.json`).

Example `targets.json`:
```json
{ "scan_targets": ["./", "./some/project"] }
```

## Database & Local Services
- Start Postgres (LTS): `docker compose up -d postgres`
- DSN: `postgres://meteor:meteor@localhost:5432/meteor_watcher`
- Init: schema files in `db/init/` run on first start; data persists in volume `db-data`.
- Health: `docker compose ps` shows status; environment overrides `POSTGRES_USER|PASSWORD|DB`.

## Coding Style & Naming
- Format: `gleam format` (or `gleam format --check` in CI).
- Indentation: 2 spaces. Modules/files: lowercase_with_underscores. Functions: `snake_case`. Types: `CamelCase`.
- Keep functions small and pure where possible; place new modules in the closest matching folder.

## Testing Guidelines
- Framework: `gleeunit` via `gleam test`.
- Location: under `test/`, files end with `_test.gleam` and mirror source layout.
- Conventions: deterministic, no network; prefer mocked inputs (e.g., CSV strings) and controlled file IO. Use `test/integration/` for slower, IO-heavy cases.

## Commit & PR Guidelines
- Commits: imperative, present tense and scoped (e.g., "Add version range checks").
- PRs: clear summary, linked issues, repro steps, and before/after notes. Include tests and doc updates.
- Pre-flight: `gleam format && gleam test && gleam build` should pass locally.

## Architecture Overview
- Flow: `collectors` → `file_manager` cache → `vuln_extractors` → `index_searcher` → CLI output in `meteor_watcher.main/0`. Postgres (`db/init`) is available for persisting scan runs and matches.
