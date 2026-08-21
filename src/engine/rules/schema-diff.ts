import { config } from "../../config";
import {
  FindingDraft,
  PublicGrantRow,
  Rule,
  SchemaSnapshot,
  SnapshotTable,
} from "../types";

export function buildSnapshot(
  schemaObjects: Parameters<typeof tablesFromRows>[0],
  publicGrants: PublicGrantRow[],
  capturedAt: string
): SchemaSnapshot {
  return {
    capturedAt,
    tables: tablesFromRows(schemaObjects),
    publicGrants,
  };
}

function tablesFromRows(
  rows: Array<{
    schemaName: string;
    tableName: string;
    rlsEnabled: boolean;
    columnName: string | null;
  }>
): SnapshotTable[] {
  const map = new Map<string, SnapshotTable>();
  for (const r of rows) {
    const key = `${r.schemaName}.${r.tableName}`;
    let t = map.get(key);
    if (!t) {
      t = { schema: r.schemaName, table: r.tableName, rlsEnabled: r.rlsEnabled, columns: [] };
      map.set(key, t);
    }
    if (r.columnName && !t.columns.includes(r.columnName)) {
      t.columns.push(r.columnName);
    }
  }
  return [...map.values()].sort((a, b) =>
    `${a.schema}.${a.table}`.localeCompare(`${b.schema}.${b.table}`)
  );
}

function grantKey(g: PublicGrantRow): string {
  return `${g.objectType}:${g.schemaName}:${g.objectName}:${g.privilegeType}`;
}

function tableKey(t: { schema: string; table: string }): string {
  return `${t.schema}.${t.table}`;
}

function looksSensitive(schema: string, table: string): boolean {
  const haystack = `${schema}.${table}`.toLowerCase();
  return config.sensitiveTablePatterns.some((p) => haystack.includes(p.toLowerCase()));
}

export function diffSnapshots(
  previous: SchemaSnapshot,
  current: SchemaSnapshot
): FindingDraft[] {
  const findings: FindingDraft[] = [];

  const prevTables = new Map(previous.tables.map((t) => [tableKey(t), t]));
  const currTables = new Map(current.tables.map((t) => [tableKey(t), t]));

  const newTables = current.tables.filter((t) => !prevTables.has(tableKey(t)));
  const droppedTables = previous.tables.filter((t) => !currTables.has(tableKey(t)));

  if (newTables.length > 0) {
    const sensitiveNew = newTables.filter((t) => looksSensitive(t.schema, t.table));
    findings.push({
      id: "schema-diff/new-tables",
      title: `${newTables.length} new table(s) since last run`,
      severity: sensitiveNew.length > 0 ? "medium" : "info",
      category: "drift",
      description:
        `Tables created since the previous audit of this target.` +
        (sensitiveNew.length > 0
          ? ` ${sensitiveNew.length} match your sensitive-name patterns — verify they have RLS and correct grants.`
          : ""),
      evidence: {
        newTables: newTables.map((t) => ({
          name: tableKey(t),
          columns: t.columns.length,
          matchesSensitivePattern: looksSensitive(t.schema, t.table),
        })),
      },
      recommendation:
        "Review whether these tables are expected, and re-run a full audit to check their grants/RLS.",
    });
  }

  if (droppedTables.length > 0) {
    findings.push({
      id: "schema-diff/dropped-tables",
      title: `${droppedTables.length} table(s) removed since last run`,
      severity: "info",
      category: "drift",
      description:
        "Tables present in the previous audit no longer exist. Expected during normal development; unexpected drops can indicate an incident or a rogue migration.",
      evidence: { droppedTables: droppedTables.map(tableKey) },
      recommendation: "Confirm the removals were intentional.",
    });
  }

  // New columns on existing tables.
  const newColumns: Array<{ table: string; column: string }> = [];
  for (const t of current.tables) {
    const prev = prevTables.get(tableKey(t));
    if (!prev) continue;
    for (const col of t.columns) {
      if (!prev.columns.includes(col)) {
        newColumns.push({ table: tableKey(t), column: col });
      }
    }
  }
  if (newColumns.length > 0) {
    findings.push({
      id: "schema-diff/new-columns",
      title: `${newColumns.length} new column(s) since last run`,
      severity: "info",
      category: "drift",
      description: "Columns added to existing tables since the previous audit.",
      evidence: { newColumns },
      recommendation:
        "Check that new columns holding sensitive values follow your data-hygiene rules.",
    });
  }

  // New PUBLIC grants.
  const prevGrants = new Set(previous.publicGrants.map(grantKey));
  const newGrants = current.publicGrants.filter((g) => !prevGrants.has(grantKey(g)));
  if (newGrants.length > 0) {
    findings.push({
      id: "schema-diff/new-public-grants",
      title: `${newGrants.length} new PUBLIC grant(s) since last run`,
      severity: "high",
      category: "drift",
      description:
        "PUBLIC-facing privileges appeared since the last audit. New exposure paths deserve immediate review.",
      evidence: {
        newGrants: newGrants.map(
          (g) => `${g.schemaName}.${g.objectName}: ${g.privilegeType}`
        ),
      },
      recommendation:
        "REVOKE unintended PUBLIC grants; add explicit role-based grants instead.",
    });
  }

  return findings;
}

export const schemaDiff: Rule = {
  id: "schema-diff",
  run: (_data, ctx): FindingDraft[] => {
    if (!ctx.previousSnapshot || !ctx.currentSnapshot) return [];
    return diffSnapshots(ctx.previousSnapshot, ctx.currentSnapshot);
  },
};
