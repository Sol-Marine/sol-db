# sol-db — Postgres Security Auditor

A CLI tool that connects **read-only** to a Postgres database you own (Neon, Railway,
self-hosted) and produces a scored security report: role/grant misconfigurations,
missing RLS, weak TLS settings, outdated version/EOL status, and schema drift over time.

## Guardrails (read first)

- **Only run this against databases you own or have written authorization to test.**
  Even read-only introspection queries against someone else's production DB without
  permission is unauthorized access.
- The tool connects with a **dedicated least-privilege role** — `SELECT` on system
  catalogs only, no access to actual table data. Never reuse your app's admin credentials.
  The tool self-checks on startup and **refuses to run** if the connected role can
  `INSERT`/`UPDATE`/`DELETE` on any non-system table or is a superuser.
- Store credentials in `.env`, never commit them, never log full connection strings.
- Treat findings output as sensitive — a completed report is effectively a map of your weaknesses.

## Setup

```bash
npm install
npm run build
cp .env.example .env   # then edit .env with your read-only role's connection string
```

### Provisioning a read-only audit role on the target DB

```sql
CREATE ROLE sol_audit LOGIN PASSWORD '<strong-password>';
GRANT CONNECT ON DATABASE mydb TO sol_audit;
GRANT USAGE ON SCHEMA public TO sol_audit;
-- pg_catalog / information_schema / pg_settings are readable by default — no grants needed.
```

## Usage

```bash
# Full audit: introspect -> analyze -> persist -> write report to ./reports/
sol-db run --target b-tracker-prod

# List past runs with severity counts
sol-db history --target b-tracker-prod

# Show schema/config drift since the last stored run (does not save anything)
sol-db diff --target b-tracker-prod
```

Local dev without global install:

```bash
npm run cli -- run --target b-tracker-prod
```

## Checks (v1)

| Rule | Category | What it flags |
|---|---|---|
| `superuser-roles` | access_control | Non-system roles with `SUPERUSER` |
| `public-schema-grants` | access_control | Objects/schema with grants to `PUBLIC` |
| `missing-rls` | access_control | Sensitive-named tables without Row Level Security |
| `ssl-not-enforced` | configuration | Server SSL off, unencrypted connection, weak min TLS |
| `outdated-version` | configuration | EOL major version, missing minor patches (endoflife.date) |
| `logging-disabled` | configuration | `log_connections`/`log_disconnections`/`log_statement` off |
| `plaintext-secret-columns` | data_hygiene | Columns named like secrets but plain-text typed (heuristic) |
| `schema-diff` | drift | New/dropped tables, new columns, new PUBLIC grants vs last run |

Severity scale: `critical > high > medium > low > info`.

## Data stored locally

All persistence is local SQLite at `data/sol.db`: one row per run, findings per run,
and a serialized schema snapshot used for drift diffing. Reports land in `reports/`.

## Report output

Markdown grouped critical → info. Each finding includes description, evidence block,
and recommendation. Treat every report as confidential.
