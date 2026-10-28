# `ctf-tui` / `ctf-admin`

The operator surface from design §10: a `ratatui` terminal UI over a Postgres
database. It ingests a `.ctf` bundle, runs the same §25 offline gate as
`ctf run`, shows the section table and annotated hexdump, reports verification
status, records entitlements, and performs the event-end seal release.

The TUI is a thin front end. Every SQL statement lives in `src/db.rs` or
`src/ingest.rs`; the UI state machine in `src/app.rs` returns an `Action` and
never performs I/O itself. There is no HTTP server, no auth layer, and no
browser build.

## Quick start

```sh
# A local database; nothing in the code knows about CloudNativePG or Kubernetes.
docker run -d --name ctf-pg \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=ctf \
  -p 5432:5432 \
  postgres:17

export DATABASE_URL=postgres://postgres:postgres@localhost:5432/ctf
cargo run -p ctf-tui --bin ctf-admin
```

`--database-url` overrides `DATABASE_URL`, and `--actor <name>` sets the name
written to every audit row (default `operator`).

Migrations in `migrations/` are compiled into the binary with
`sqlx::migrate!` and applied on connect, so a fresh database needs no separate
migration step. They are plain SQL; the deployment can be a local container, a
managed Postgres, or a CloudNativePG cluster without a code change.

## Screens

| Screen | What it does |
|---|---|
| Challenges | One row per challenge version, bundle count, latest verdict |
| Ingest | Path plus optional authoring document and event secret; live per-stage progress |
| Bundle inspector | Section table, serving verdict, hexdump of the stored bytes |
| Seal release | Event-end release with a KEM secret-key file, then the release report |
| Verification | `passed` / `unverified` / `failed`, plus the §25.6 reason |
| Entitlements / audit | Append-only audit rows and the entitlement/handoff chain |

`Tab` / `Shift-Tab` move between screens, `j`/`k` move the selection, `Enter`
acts, `r` refreshes, and `q` quits. A focused text field owns typing until
`Esc` leaves it. Errors are rendered in a footer pane; a bad row or a refused
release never panics the render loop.

## Ingest rules that the code enforces

- **No gate, no pass.** A bundle is written as `passed` only when
  `ctf_generator::offline_gate` returned `Passed` in this run. Missing inputs,
  an unreadable authoring document, a version mismatch, a runtime challenge, an
  unavailable module, and every other failure to construct the gate are
  `unverified` with the reason stored in `verification.reason`.
- **Parse and integrity failures leave no bundle row.** They are
  `rejected` plus an `ingest.rejected` audit row, so a later query cannot mistake
  them for ingestible bytes.
- **Store is one transaction.** Challenge, bundle, sections, verification, and
  the `ingest.stored` audit row commit together.
- **The full bundle bytes are stored.** Re-inspection and release work from the
  database, not from a path that may have moved. `source_path` is optional and
  non-authoritative.

## Serving rule: two independent checks

`db::served_artifacts` is default-deny, per design §10:

1. The SQL query is an allowlist: `WHERE player_visible AND NOT sealed`.
2. The returned raw `flags` word is checked again by
   `db::flags_allow_serving`, which requires `PLAYER_VISIBLE` and rejects
   `SEALED`.

A row whose columns disagree with its bitfield (a manual `UPDATE`, a future
writer's bug) makes it through the SQL and is dropped by the second check.
Nothing in the crate implements "serve everything except …". Both
`player_visible` and `sealed` are stored as their own columns during ingest, so
the two checks read independent facts.

`EXTERNAL` artifacts are returned as metadata when they are `PLAYER_VISIBLE`
and unsealed; the caller can see the `EXTERNAL` bit and knows their bytes are
not in the bundle. Their mirrors are manifest data, not database rows.

## Compile-time SQL and the offline cache

Design §11 names `sqlx` with compile-time-checked SQL. Every statement in
`src/db.rs` and `src/ingest.rs` uses `sqlx::query!`, `query_as!`, or
`query_scalar!`, so a column name, a type, or a nullability mismatch is a
compile error rather than a runtime one. The test files keep runtime
`sqlx::query` where a statement is generated (`CREATE SCHEMA`, `SET search_path`)
or is itself the subject of the test; production SQL is macro-checked.

The checked metadata is committed in `.sqlx/` at the workspace root, so a
database-free build still checks every statement against the schema:

```sh
sqlx --version        # 0.8.x, matching the `sqlx` dependency
# With Postgres running, after changing SQL or migrations:
cargo sqlx prepare --workspace      # from ctf-format/, writes ctf-format/.sqlx
git add .sqlx

# Any build without a database:
SQLX_OFFLINE=true cargo check --workspace
```

`.sqlx/` must be regenerated whenever a statement changes or a migration lands.
CI's Ubuntu/macOS matrix sets `SQLX_OFFLINE=true` and needs no database. The
`database` job sets `DATABASE_URL` and compiles the same statements live against
Postgres 17 before running the DB-backed tests, so a stale cache is caught rather
than silently shipped.

Migrations are compiled into the binary with `sqlx::migrate!`, which needs only
the `migrate` feature; the query macros need `macros`.

There is no ORM and no query builder. A column rename lands in `migrations/`
and `src/db.rs`, nowhere else.

## Tests

The DB tests are gated on `CTF_TEST_DATABASE_URL`; without it they return
early, so `cargo test --workspace` stays green on a machine with no Postgres.
Each test creates a uniquely named schema (`ctf_tui_test_<pid>_<n>`), so tests
run in parallel against one database without touching each other's rows.

```sh
docker run -d --name ctf-pg \
  -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=ctf -p 5432:5432 postgres:17
export CTF_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/ctf

cargo test -p ctf-tui
cargo test --workspace            # DB tests skip without the variable
```

The headless `tests/ui.rs` renders every screen through `TestBackend`, so a
broken layout or an unescaped control character fails in CI rather than in an
operator's terminal.

## Security posture

Operator access is SSH to a host running `ctf-admin`; there is no listening
socket to attack. The process holds the database credentials and, only while an
operator is actively releasing, the offline seal key file. Sealed sections and
writeups remain encrypted in the database and are not decrypted by inspection.
The TUI never prints a secret key, and the release report names members and
sizes rather than embedding plaintext.
