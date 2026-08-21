import { FindingDraft, RawData, Rule } from "../types";

/**
 * Flags non-system roles with SUPERUSER.
 * Note: managed providers (Neon/Railway) expose their own admin roles;
 * those are called out separately so they can be triaged quickly.
 */
const KNOWN_PROVIDER_ADMINS = new Set([
  "cloud_admin",
  "web_admin",
  "admin",
  "root",
  "postgres",
  "azure_pg_admin",
  "rds_superuser",
]);

export const superuserRoles: Rule = {
  id: "superuser-roles",
  run: (data: RawData): FindingDraft[] => {
    const supers = data.roles.filter((r) => r.rolsuper);
    if (supers.length === 0) return [];

    const providerAdmins = supers.filter((r) => KNOWN_PROVIDER_ADMINS.has(r.rolname));
    const ownRoles = supers.filter((r) => !KNOWN_PROVIDER_ADMINS.has(r.rolname));

    const findings: FindingDraft[] = [];

    if (ownRoles.length > 0) {
      findings.push({
        id: "superuser-roles",
        title: `${ownRoles.length} role(s) have SUPERUSER`,
        severity: "high",
        category: "access_control",
        description:
          "SUPERUSER bypasses every permission check inside Postgres, including RLS. " +
          "Application or personal roles should never hold it.",
        evidence: {
          roles: ownRoles.map((r) => ({
            name: r.rolname,
            canLogin: r.rolcanlogin,
            createRole: r.rolcreaterole,
            createDb: r.rolcreatedb,
            replication: r.rolreplication,
            bypassRls: r.rolbypassrls,
          })),
        },
        recommendation:
          "Revoke SUPERUSER from any role that does not strictly require it: ALTER ROLE <name> NOSUPERUSER. Prefer granting specific privileges.",
      });
    }

    if (providerAdmins.length > 0) {
      findings.push({
        id: "superuser-roles/provider-admins",
        title: `${providerAdmins.length} provider-managed admin role(s) detected`,
        severity: "info",
        category: "access_control",
        description:
          "Managed Postgres providers include their own superuser accounts for platform operations. This is usually expected, but verify against your provider's documentation.",
        evidence: { roles: providerAdmins.map((r) => r.rolname) },
        recommendation:
          "Confirm these belong to your hosting provider. No action needed if expected; investigate immediately if you did not choose this provider.",
      });
    }

    return findings;
  },
};
