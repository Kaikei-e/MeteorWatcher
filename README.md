# Meteor Watcher — offline daily vuln feed (alpha)

**Status:** early WIP.
**What it does today:**

* Downloads OSV’s **`modified_id.csv`** and fetches the changed advisory JSON files into a local cache. ([Google GitHub][1])
  **Next (planned):**
* Recursively walk a target directory and **search for potential matches** (lockfiles / manifests first; optional text search) against the locally cached advisories.

## Why this approach?

* **Privacy-first**: we never upload your dependency list; we only **pull** OSV data dumps and match **locally**. ([Google GitHub][1])
* **Simple & fast deltas**: `modified_id.csv` lists “recently added/changed” advisories as `<iso8601>,<ecosystem>/<id>`, which we resolve to `<ecosystem>/<id>.json`. ([Google GitHub][1])

## Quick start

```bash
# Build (Gleam on BEAM)
gleam deps download
gleam build

# Fetch the latest delta (stores state & JSON cache under ./.meteor_watcher/)
gleam run fetch
```

> HTTP is implemented with `gleam_httpc`. Filesystem walking will use `fswalk`. ([HexDocs][2])

### Database (Docker Compose)

```bash
# Start local Postgres (LTS)
docker compose up -d postgres

# Check status/health
docker compose ps
```

- DSN: `postgres://meteor:meteor@localhost:5432/meteor_watcher`
- Config: copy `.env.example` to `.env` to override `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, or `DATABASE_URL`.
- Init: schema is applied from `db/init/` on first start; data persists in the `db-data` volume. See `compose.yaml`.

## Planned scanning (MVP)

1. **Collect patterns** from advisory JSON: for each `affected[].package` take `(ecosystem, name)` and any explicit `versions`. (OSV: a version is affected if it’s within any `ranges` or listed in `versions`.) ([OSSF][3])
2. **Search order (low-noise first)**

   * Lockfiles / manifests only (e.g., `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `Cargo.lock`, `go.mod`/`go.sum`, `poetry.lock`, `Pipfile.lock`, `pom.xml`, Gradle lockfile).
   * Then (optional) broader **text search** in the repo (skip `node_modules`, `target`, `build`, `.git`, `dist`, etc.).
3. **Matcher**

   * Start with exact/normalized **name hits** + nearby **version** capture (per ecosystem).
   * For multi-pattern text search use **Aho-Corasick** (linear-time over many patterns); refine later with per-ecosystem parsers. ([競技プログラミングのアルゴリズム][4])

### Notes & limitations

* Plain text search **can yield false positives**. Lockfile/manifest parsing should be preferred; later we’ll add PURL-based normalization and per-ecosystem comparators. ([GitHub][5])
* OSV schema carries exact matching semantics (`ranges` / `versions`); the MVP will begin with name+version string hits, then evolve to proper range evaluation. ([OSSF][3])

## Configuration (alpha)

```toml
# meteor_watcher.toml
cache_dir = ".meteor_watcher/cache"
state_file = ".meteor_watcher/state.json"

# scan target (planned)
scan_path = "."
ignore_dirs = ["node_modules", "target", "build", "dist", ".git"]
```

## Roadmap

* Lockfile/manifest extractors per ecosystem, then **range evaluation** per OSV spec. ([OSSF][3])
* Optional **PURL** normalization for consistent IDs across ecosystems. ([GitHub][5])
* Aho-Corasick matcher for many names; fall back to ecosystem parsers to confirm. ([競技プログラミングのアルゴリズム][4])

## References

* OSV data dumps & `modified_id.csv` format. ([Google GitHub][1])
* OSV schema (`affected.ranges|versions`, evaluation rule). ([OSSF][3])
* Package URL (PURL) spec. ([GitHub][5])
* Gleam HTTP / FS walk libs. ([HexDocs][2])
