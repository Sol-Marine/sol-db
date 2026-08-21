export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category = "access_control" | "configuration" | "data_hygiene" | "drift";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Finding {
  /** stable slug, e.g. "public-schema-write-grant" or "missing-rls/public.users" */
  id: string;
  title: string;
  severity: Severity;
  category: Category;
  description: string;
  evidence: Record<string, unknown>;
  recommendation: string;
  detectedAt: string;
}

export type FindingDraft = Omit<Finding, "detectedAt">;

export interface RoleRow {
  rolname: string;
  rolsuper: boolean;
  rolcreaterole: boolean;
  rolcreatedb: boolean;
  rolcanlogin: boolean;
  rolreplication: boolean;
  rolbypassrls: boolean;
  rolvaliduntil: string | null;
}

export interface PublicGrantRow {
  objectType: "relation" | "schema";
  schemaName: string;
  objectName: string;
  relkind: string | null;
  privilegeType: string;
}

export interface SettingRow {
  name: string;
  setting: string;
  unit: string | null;
}

export interface SchemaObjectRow {
  schemaName: string;
  tableName: string;
  relkind: string;
  rlsEnabled: boolean;
  rlsForced: boolean;
  columnName: string | null;
  dataType: string | null;
}

export interface RawData {
  versionString: string;
  serverVersionNum: number;
  roles: RoleRow[];
  publicGrants: PublicGrantRow[];
  settings: SettingRow[];
  schemaObjects: SchemaObjectRow[];
  connectionSsl: boolean;
}

export interface SnapshotTable {
  schema: string;
  table: string;
  rlsEnabled: boolean;
  columns: string[];
}

export interface SchemaSnapshot {
  capturedAt: string;
  tables: SnapshotTable[];
  publicGrants: PublicGrantRow[];
}

export interface RuleContext {
  previousSnapshot: SchemaSnapshot | null;
  currentSnapshot?: SchemaSnapshot;
}

export interface Rule {
  id: string;
  run: (data: RawData, ctx: RuleContext) => FindingDraft[] | Promise<FindingDraft[]>;
}
