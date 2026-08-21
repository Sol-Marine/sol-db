import { FindingDraft, RawData, Rule } from "../types";

const WRITE_PERMS = new Set(["INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]);

function relKindLabel(relkind: string | null): string {
  switch (relkind) {
    case "r":
      return "table";
    case "p":
      return "partitioned table";
    case "v":
      return "view";
    case "m":
      return "materialized view";
    case "S":
      return "sequence";
    case "f":
      return "foreign table";
    default:
      return "relation";
  }
}

export const publicSchemaGrants: Rule = {
  id: "public-schema-grants",
  run: (data: RawData): FindingDraft[] => {
    const findings: FindingDraft[] = [];
    const relationGrants = data.publicGrants.filter((g) => g.objectType === "relation");
    const schemaGrants = data.publicGrants.filter((g) => g.objectType === "schema");

    const writeGrants = relationGrants.filter((g) => WRITE_PERMS.has(g.privilegeType));
    if (writeGrants.length > 0) {
      const objects = [
        ...new Set(
          writeGrants.map(
            (g) =>
              `${g.schemaName}.${g.objectName} (${relKindLabel(g.relkind)}: ${g.privilegeType})`
          )
        ),
      ];
      findings.push({
        id: "public-schema-write-grant",
        title: `PUBLIC can write to ${objects.length} object(s)`,
        severity: "critical",
        category: "access_control",
        description:
          "Every role in the cluster — including future ones — holds write privileges on these objects. Any compromised low-privilege role can modify or destroy this data.",
        evidence: { objects },
        recommendation:
          "REVOKE ALL ON <object> FROM PUBLIC; then grant explicitly to the roles that need access.",
      });
    }

    const readGrants = relationGrants.filter((g) => g.privilegeType === "SELECT");
    if (readGrants.length > 0 && writeGrants.length === 0) {
      const objects = [
        ...new Set(readGrants.map((g) => `${g.schemaName}.${g.objectName}`)),
      ];
      findings.push({
        id: "public-schema-read-grant",
        title: `PUBLIC can read ${objects.length} object(s)`,
        severity: "medium",
        category: "access_control",
        description:
          "SELECT is granted to PUBLIC on these objects, so any role (and anything that gains a role) can read the full contents.",
        evidence: { objects },
        recommendation:
          "If unintended: REVOKE SELECT ON <object> FROM PUBLIC; grant to specific roles instead.",
      });
    }

    const createOnSchema = schemaGrants.filter((g) => g.privilegeType === "CREATE");
    if (createOnSchema.length > 0) {
      const schemas = [...new Set(createOnSchema.map((g) => g.schemaName))];
      findings.push({
        id: "public-schema-create-grant",
        title: `PUBLIC has CREATE on ${schemas.length} schema(s)`,
        severity: "high",
        category: "access_control",
        description:
          "Any role can create objects in these schemas. Combined with search_path tricks this is a common privilege-escalation primitive.",
        evidence: { schemas },
        recommendation:
          "REVOKE CREATE ON SCHEMA <schema> FROM PUBLIC; (Postgres 15+ revokes this by default on the public schema).",
      });
    }

    return findings;
  },
};
