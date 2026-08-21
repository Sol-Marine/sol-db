import { config } from "../../config";
import { FindingDraft, RawData, Rule } from "../types";

function tableMatchesSensitive(schema: string, table: string): boolean {
  const haystack = `${schema}.${table}`.toLowerCase();
  return config.sensitiveTablePatterns.some((p) => haystack.includes(p.toLowerCase()));
}

export const missingRls: Rule = {
  id: "missing-rls",
  run: (data: RawData): FindingDraft[] => {
    // Collapse rows to one entry per table.
    const tables = new Map<
      string,
      { schemaName: string; tableName: string; rlsEnabled: boolean; rlsForced: boolean }
    >();
    for (const row of data.schemaObjects) {
      const key = `${row.schemaName}.${row.tableName}`;
      if (!tables.has(key)) {
        tables.set(key, {
          schemaName: row.schemaName,
          tableName: row.tableName,
          rlsEnabled: row.rlsEnabled,
          rlsForced: row.rlsForced,
        });
      }
    }

    const findings: FindingDraft[] = [];
    for (const t of tables.values()) {
      if (t.rlsEnabled) continue;
      if (!tableMatchesSensitive(t.schemaName, t.tableName)) continue;

      findings.push({
        id: `missing-rls/${t.schemaName}.${t.tableName}`,
        title: `No RLS on sensitive-looking table ${t.schemaName}.${t.tableName}`,
        severity: "high",
        category: "access_control",
        description:
          "Row Level Security is disabled on a table whose name suggests it holds sensitive data " +
          "(matched your configurable pattern list). Any role with SELECT on it reads every row.",
        evidence: {
          schema: t.schemaName,
          table: t.tableName,
          rlsEnabled: t.rlsEnabled,
          rlsForced: t.rlsForced,
        },
        recommendation:
          "If the table truly holds per-tenant/per-user data: ALTER TABLE ... ENABLE ROW LEVEL SECURITY; add policies; and consider FORCE ROW LEVEL SECURITY. " +
          "Note RLS does not bind the table owner or superusers unless forced.",
      });
    }
    return findings;
  },
};
