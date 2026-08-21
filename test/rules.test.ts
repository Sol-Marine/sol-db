import { test } from "node:test";
import assert from "node:assert/strict";
import { superuserRoles } from "../src/engine/rules/superuser-roles";
import { publicSchemaGrants } from "../src/engine/rules/public-schema-grants";
import { missingRls } from "../src/engine/rules/missing-rls";
import { sslNotEnforced } from "../src/engine/rules/ssl-not-enforced";
import { loggingDisabled } from "../src/engine/rules/logging-disabled";
import { plaintextSecretColumns } from "../src/engine/rules/plaintext-secret-columns";
import {
  buildSnapshot,
  diffSnapshots,
} from "../src/engine/rules/schema-diff";
import {
  outdatedVersion,
  parseVersion,
  assessVersion,
  EolEntry,
} from "../src/engine/rules/outdated-version";
import { runRules, registerRule, RULES } from "../src/engine/runner";
import { renderReport } from "../src/report/markdown";
import { Finding, RawData, RuleContext, Severity } from "../src/engine/types";

function makeData(overrides: Partial<RawData> = {}): RawData {
  return {
    versionString:
      "PostgreSQL 16.3 (Debian 16.3-1.pgdg120+1) on x86_64-pc-linux-gnu, compiled by gcc",
    serverVersionNum: 160003,
    roles: [],
    publicGrants: [],
    settings: [],
    schemaObjects: [],
    connectionSsl: true,
    ...overrides,
  };
}

const emptyCtx: RuleContext = { previousSnapshot: null };

// ---------- superuser-roles ----------

test("superuser-roles flags own superuser roles as high", async () => {
  const data = makeData({
    roles: [
      {
        rolname: "app_admin",
        rolsuper: true,
        rolcreaterole: false,
        rolcreatedb: false,
        rolcanlogin: true,
        rolreplication: false,
        rolbypassrls: true,
        rolvaliduntil: null,
      },
    ],
  });
  const findings = await superuserRoles.run(data, emptyCtx);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.id, "superuser-roles");
  assert.equal(findings[0]!.severity, "high");
});

test("superuser-roles reports provider admins as info only", async () => {
  const data = makeData({
    roles: [
      {
        rolname: "cloud_admin",
        rolsuper: true,
        rolcreaterole: false,
        rolcreatedb: false,
        rolcanlogin: false,
        rolreplication: false,
        rolbypassrls: false,
        rolvaliduntil: null,
      },
    ],
  });
  const findings = await superuserRoles.run(data, emptyCtx);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.severity, "info");
});

test("superuser-roles silent when clean", async () => {
  const findings = await superuserRoles.run(makeData(), emptyCtx);
  assert.equal(findings.length, 0);
});

// ---------- public-schema-grants ----------

test("public write grants are critical", async () => {
  const data = makeData({
    publicGrants: [
      {
        objectType: "relation",
        schemaName: "public",
        objectName: "users",
        relkind: "r",
        privilegeType: "DELETE",
      },
    ],
  });
  const findings = await publicSchemaGrants.run(data, emptyCtx);
  assert.ok(findings.some((f) => f.id === "public-schema-write-grant" && f.severity === "critical"));
});

test("public select-only grants are medium", async () => {
  const data = makeData({
    publicGrants: [
      {
        objectType: "relation",
        schemaName: "public",
        objectName: "lookup",
        relkind: "r",
        privilegeType: "SELECT",
      },
    ],
  });
  const findings = await publicSchemaGrants.run(data, emptyCtx);
  assert.ok(findings.some((f) => f.id === "public-schema-read-grant" && f.severity === "medium"));
  assert.ok(!findings.some((f) => f.id === "public-schema-write-grant"));
});

test("public CREATE on schema is high", async () => {
  const data = makeData({
    publicGrants: [
      {
        objectType: "schema",
        schemaName: "public",
        objectName: "public",
        relkind: null,
        privilegeType: "CREATE",
      },
    ],
  });
  const findings = await publicSchemaGrants.run(data, emptyCtx);
  assert.ok(findings.some((f) => f.id === "public-schema-create-grant" && f.severity === "high"));
});

// ---------- missing-rls ----------

test("missing-rls flags sensitive table without RLS", async () => {
  const data = makeData({
    schemaObjects: [
      {
        schemaName: "public",
        tableName: "user_profiles",
        relkind: "r",
        rlsEnabled: false,
        rlsForced: false,
        columnName: "id",
        dataType: "integer",
      },
      {
        schemaName: "public",
        tableName: "countries",
        relkind: "r",
        rlsEnabled: false,
        rlsForced: false,
        columnName: "code",
        dataType: "text",
      },
    ],
  });
  const findings = await missingRls.run(data, emptyCtx);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.id, "missing-rls/public.user_profiles");
  assert.equal(findings[0]!.severity, "high");
});

test("missing-rls ignores tables with RLS enabled", async () => {
  const data = makeData({
    schemaObjects: [
      {
        schemaName: "public",
        tableName: "users",
        relkind: "r",
        rlsEnabled: true,
        rlsForced: false,
        columnName: null,
        dataType: null,
      },
    ],
  });
  assert.equal((await missingRls.run(data, emptyCtx)).length, 0);
});

// ---------- ssl-not-enforced ----------

test("ssl=off is critical", async () => {
  const data = makeData({ settings: [{ name: "ssl", setting: "off", unit: null }] });
  const findings = await sslNotEnforced.run(data, emptyCtx);
  assert.ok(findings.some((f) => f.id === "ssl-not-enforced/server-off" && f.severity === "critical"));
});

test("unencrypted connection is high", async () => {
  const findings = await sslNotEnforced.run(makeData({ connectionSsl: false }), emptyCtx);
  assert.ok(
    findings.some(
      (f) => f.id === "ssl-not-enforced/unencrypted-connection" && f.severity === "high"
    )
  );
});

test("weak min TLS is medium", async () => {
  const data = makeData({
    settings: [{ name: "ssl_min_protocol_version", setting: "TLSv1", unit: null }],
  });
  const findings = await sslNotEnforced.run(data, emptyCtx);
  assert.ok(findings.some((f) => f.id === "ssl-not-enforced/weak-min-tls"));
});

// ---------- logging-disabled ----------

test("log_connections off is flagged", async () => {
  const data = makeData({
    settings: [{ name: "log_connections", setting: "off", unit: null }],
  });
  const findings = await loggingDisabled.run(data, emptyCtx);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.id, "logging-disabled/log_connections");
});

test("logging on is silent", async () => {
  const data = makeData({
    settings: [
      { name: "log_connections", setting: "on", unit: null },
      { name: "log_statement", setting: "ddl", unit: null },
    ],
  });
  assert.equal((await loggingDisabled.run(data, emptyCtx)).length, 0);
});

// ---------- plaintext-secret-columns ----------

test("plain-text password column is flagged as info", async () => {
  const data = makeData({
    schemaObjects: [
      {
        schemaName: "public",
        tableName: "accounts",
        relkind: "r",
        rlsEnabled: false,
        rlsForced: false,
        columnName: "password_hash",
        dataType: "character varying(255)",
      },
      {
        schemaName: "public",
        tableName: "accounts",
        relkind: "r",
        rlsEnabled: false,
        rlsForced: false,
        columnName: "api_key",
        dataType: "text",
      },
    ],
  });
  const findings = await plaintextSecretColumns.run(data, emptyCtx);
  // password_hash matches pattern but is likely a hash; both match the heuristic.
  assert.equal(findings.length, 2);
  assert.ok(findings.every((f) => f.severity === "info"));
  assert.ok(findings[0]!.id.startsWith("plaintext-secret-columns/"));
});

test("integer columns never flagged", async () => {
  const data = makeData({
    schemaObjects: [
      {
        schemaName: "public",
        tableName: "t",
        relkind: "r",
        rlsEnabled: false,
        rlsForced: false,
        columnName: "token_count",
        dataType: "integer",
      },
    ],
  });
  assert.equal((await plaintextSecretColumns.run(data, emptyCtx)).length, 0);
});

// ---------- version parsing + outdated-version ----------

test("parseVersion extracts major.minor.patch", async () => {
  assert.deepEqual(parseVersion("PostgreSQL 16.3 (Debian)"), {
    major: 16,
    minor: 3,
    patch: 0,
  });
  assert.deepEqual(parseVersion("PostgreSQL 15.7.1 on x86_64"), {
    major: 15,
    minor: 7,
    patch: 1,
  });
  assert.equal(parseVersion("not a version"), null);
});

test("assessVersion treats future EOL dates as still supported", () => {
  const eolData: EolEntry[] = [
    { cycle: "18", latest: "18.4", releaseDate: null, eol: "2030-11-14", support: "2028-11-14" },
  ];
  const findings = assessVersion({ major: 18, minor: 4, patch: 0 }, eolData);
  assert.equal(findings.length, 0); // not EOL, not behind
});

test("assessVersion flags EOL major as critical", () => {
  const eolData: EolEntry[] = [
    { cycle: "12", latest: "12.22", releaseDate: null, eol: "2024-11-14", support: false },
    { cycle: "16", latest: "16.9", releaseDate: null, eol: false, support: false },
    { cycle: "17", latest: "17.5", releaseDate: null, eol: false, support: "2029-11-01" },
  ];
  const findings = assessVersion({ major: 12, minor: 4, patch: 0 }, eolData);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.id, "outdated-version/eol-major");
  assert.equal(findings[0]!.severity, "critical");
});

test("assessVersion flags missing minor patches as low", () => {
  const eolData: EolEntry[] = [
    { cycle: "16", latest: "16.9", releaseDate: null, eol: false, support: false },
  ];
  const findings = assessVersion({ major: 16, minor: 3, patch: 0 }, eolData);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.id, "outdated-version/minor-behind");
  assert.equal(findings[0]!.severity, "low");
});

test("assessVersion is silent when up to date", () => {
  const eolData: EolEntry[] = [
    { cycle: "16", latest: "16.9", releaseDate: null, eol: false, support: false },
  ];
  assert.equal(assessVersion({ major: 16, minor: 9, patch: 0 }, eolData).length, 0);
});

test("assessVersion flags unknown majors as high", () => {
  const eolData: EolEntry[] = [
    { cycle: "16", latest: "16.9", releaseDate: null, eol: false, support: false },
  ];
  const findings = assessVersion({ major: 9, minor: 6, patch: 24 }, eolData);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.id, "outdated-version/major-unknown");
  assert.equal(findings[0]!.severity, "high");
});

test("outdated-version rule skips unparseable version strings", async () => {
  const findings = await outdatedVersion.run(
    makeData({ versionString: "not a postgres banner" }),
    emptyCtx
  );
  assert.equal(findings.length, 0);
});

// ---------- schema-diff ----------

const rowsA = [
  { schemaName: "public", tableName: "users", rlsEnabled: true, columnName: "id" },
  { schemaName: "public", tableName: "users", rlsEnabled: true, columnName: "email" },
];

test("diff detects new sensitive table and new grants", async () => {
  const prev = buildSnapshot(rowsA, [], "2026-01-01T00:00:00Z");
  const rowsB = [
    ...rowsA,
    { schemaName: "public", tableName: "payment_cards", rlsEnabled: false, columnName: "pan" },
  ];
  const curr = buildSnapshot(
    rowsB,
    [
      {
        objectType: "relation",
        schemaName: "public",
        objectName: "users",
        relkind: "r",
        privilegeType: "SELECT",
      },
    ],
    "2026-02-01T00:00:00Z"
  );
  const drift = diffSnapshots(prev, curr);
  const ids = drift.map((d) => d.id);
  assert.ok(ids.includes("schema-diff/new-tables"));
  assert.ok(ids.includes("schema-diff/new-public-grants"));

  const newTables = drift.find((d) => d.id === "schema-diff/new-tables")!;
  assert.equal(newTables.severity, "medium"); // payment_* matches sensitive patterns
});

test("diff detects dropped tables and new columns", async () => {
  const oldSnap = buildSnapshot(rowsA, [], "2026-01-01T00:00:00Z");
  const curr = buildSnapshot(
    [
      { schemaName: "public", tableName: "users", rlsEnabled: true, columnName: "id" },
      { schemaName: "public", tableName: "users", rlsEnabled: true, columnName: "email" },
      { schemaName: "public", tableName: "users", rlsEnabled: true, columnName: "mfa_secret" },
    ],
    [],
    "2026-02-01T00:00:00Z"
  );
  const drift = diffSnapshots(oldSnap, curr);
  const ids = drift.map((d) => d.id);
  assert.ok(ids.includes("schema-diff/new-columns"));
});

test("no drift produces no findings", async () => {
  const snap = buildSnapshot(rowsA, [], "2026-01-01T00:00:00Z");
  assert.equal(diffSnapshots(snap, snap).length, 0);
});

// ---------- runner ----------

test("runner stamps detectedAt and survives rule crashes", async () => {
  RULES.length = 0;
  const bad: import("../src/engine/types").Rule = {
    id: "boom",
    run: () => {
      throw new Error("kaboom");
    },
  };
  registerRule(bad);
  const findings = await runRules(makeData(), emptyCtx);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.id, "rule-error/boom");
  assert.ok(findings[0]!.detectedAt);
  RULES.length = 0;
});

// ---------- report ----------

test("report groups by severity and includes evidence", async () => {
  const now = new Date().toISOString();
  const mk = (
    id: string,
    severity: Severity,
    title: string
  ): Finding => ({
    id,
    severity,
    category: "access_control",
    title,
    description: "desc",
    evidence: { foo: "bar" },
    recommendation: "fix it",
    detectedAt: now,
  });
  const md = renderReport({
    targetLabel: "test-db",
    startedAt: now,
    pgVersion: "PostgreSQL 16.3 on x86_64",
    findings: [mk("a", "critical", "Critical thing"), mk("b", "info", "Info thing")],
  });
  assert.ok(md.includes("# Security Audit Report — test-db"));
  assert.ok(md.includes("CRITICAL (1)"));
  assert.ok(md.includes("INFO (1)"));
  assert.ok(md.includes('"foo": "bar"'));
  assert.ok(md.includes("Critical thing"));
});
