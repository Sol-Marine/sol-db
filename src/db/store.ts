import Database from "better-sqlite3";
import * as fs from "fs";
import * as path from "path";
import { Finding, SchemaSnapshot, Severity } from "../engine/types";

export interface RunSummary {
  id: number;
  targetLabel: string;
  startedAt: string;
  finishedAt: string | null;
  pgVersion: string | null;
  counts: Record<Severity, number>;
}

interface RunRow {
  id: number;
  target_label: string;
  started_at: string;
  finished_at: string | null;
  pg_version: string | null;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export class FindingsStore {
  private db: Database.Database;

  constructor(dataDir: string) {
    fs.mkdirSync(dataDir, { recursive: true });
    this.db = new Database(path.join(dataDir, "sol.db"));
    this.db.pragma("journal_mode = WAL");
    this.migrate();
  }

  private migrate(): void {
    // __dirname = <root>/dist/src/db when compiled -> project root is 3 levels up.
    const migrationPath = path.join(
      __dirname,
      "..",
      "..",
      "..",
      "migrations",
      "001_init.sql"
    );
    const sql = fs.readFileSync(migrationPath, "utf8");
    this.db.exec(sql);
  }

  createRun(targetLabel: string, startedAt: string): number {
    const res = this.db
      .prepare("INSERT INTO runs (target_label, started_at) VALUES (?, ?)")
      .run(targetLabel, startedAt);
    return Number(res.lastInsertRowid);
  }

  finishRun(runId: number, finishedAt: string, pgVersion: string): void {
    this.db
      .prepare("UPDATE runs SET finished_at = ?, pg_version = ? WHERE id = ?")
      .run(finishedAt, pgVersion, runId);
  }

  saveFindings(runId: number, findings: Finding[]): void {
    const stmt = this.db.prepare(
      `INSERT INTO findings (run_id, finding_key, severity, category, title, description, evidence_json, recommendation)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );
    const insertMany = this.db.transaction((items: Finding[]) => {
      for (const f of items) {
        stmt.run(
          runId,
          f.id,
          f.severity,
          f.category,
          f.title,
          f.description,
          JSON.stringify(f.evidence),
          f.recommendation
        );
      }
    });
    insertMany(findings);
  }

  saveSnapshot(runId: number, snapshot: SchemaSnapshot): void {
    this.db
      .prepare("INSERT INTO schema_snapshots (run_id, snapshot_json) VALUES (?, ?)")
      .run(runId, JSON.stringify(snapshot));
  }

  getLatestRunWithSnapshot(targetLabel: string): {
    runId: number;
    snapshot: SchemaSnapshot;
  } | null {
    const row = this.db
      .prepare<[string], RunRow>(
        `SELECT r.* FROM runs r
         JOIN schema_snapshots s ON s.run_id = r.id
         WHERE r.target_label = ?
         ORDER BY r.id DESC LIMIT 1`
      )
      .get(targetLabel);
    if (!row) return null;
    const snapRow = this.db
      .prepare<[number], { snapshot_json: string }>(
        "SELECT snapshot_json FROM schema_snapshots WHERE run_id = ? ORDER BY id DESC LIMIT 1"
      )
      .get(row.id);
    if (!snapRow) return null;
    return {
      runId: row.id,
      snapshot: JSON.parse(snapRow.snapshot_json) as SchemaSnapshot,
    };
  }

  listRuns(targetLabel?: string): RunSummary[] {
    const rows = targetLabel
      ? this.db
          .prepare<[string], RunRow>(
            "SELECT * FROM runs WHERE target_label = ? ORDER BY id DESC"
          )
          .all(targetLabel)
      : this.db.prepare<[], RunRow>("SELECT * FROM runs ORDER BY id DESC").all();

    const countStmt = this.db.prepare<
      [number],
      { severity: string; n: number }
    >("SELECT severity, COUNT(*) AS n FROM findings WHERE run_id = ? GROUP BY severity");

    return rows.map((r) => {
      const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<
        Severity,
        number
      >;
      for (const c of countStmt.all(r.id)) {
        if ((SEVERITIES as string[]).includes(c.severity)) {
          counts[c.severity as Severity] = c.n;
        }
      }
      return {
        id: r.id,
        targetLabel: r.target_label,
        startedAt: r.started_at,
        finishedAt: r.finished_at,
        pgVersion: r.pg_version,
        counts,
      };
    });
  }

  close(): void {
    this.db.close();
  }
}
