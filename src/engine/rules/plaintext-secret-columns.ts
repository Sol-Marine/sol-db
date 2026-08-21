import { config } from "../../config";
import { FindingDraft, RawData, Rule } from "../types";

const PLAIN_TEXT_TYPES = new Set([
  "text",
  "character varying",
  "character",
  "varchar",
  "citext",
]);

function columnLooksSecret(columnName: string): boolean {
  const name = columnName.toLowerCase();
  return config.secretColumnPatterns.some((p) => name.includes(p.toLowerCase()));
}

function baseType(dataType: string): string {
  // "character varying(255)[]" -> "character varying"
  return dataType
    .replace(/\(.*?\)/g, "")
    .replace(/\[\d*\]/g, "")
    .trim();
}

export const plaintextSecretColumns: Rule = {
  id: "plaintext-secret-columns",
  run: (data: RawData): FindingDraft[] => {
    const seen = new Set<string>();
    const findings: FindingDraft[] = [];

    for (const row of data.schemaObjects) {
      if (!row.columnName || !row.dataType) continue;
      if (!PLAIN_TEXT_TYPES.has(baseType(row.dataType))) continue;
      if (!columnLooksSecret(row.columnName)) continue;

      const key = `${row.schemaName}.${row.tableName}.${row.columnName}`;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push({
        id: `plaintext-secret-columns/${key}`,
        title: `Possible plain-text secret column: ${key}`,
        severity: "info",
        category: "data_hygiene",
        description:
          "Column name suggests a secret/credential but its type is plain text. This is a heuristic flag only — it may be a hash, a token reference, or a false positive. Review manually; sol-db never reads table contents.",
        evidence: {
          schema: row.schemaName,
          table: row.tableName,
          column: row.columnName,
          dataType: row.dataType,
        },
        recommendation:
          "Verify the column stores only irreversible hashes (bcrypt/argon2) or references, not raw secrets. If raw secrets are stored, migrate to hashing or a secrets manager and rotate exposed values.",
      });
    }
    return findings;
  },
};
