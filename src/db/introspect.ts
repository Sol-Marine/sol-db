import { Client } from "pg";
import {
  PublicGrantRow,
  RawData,
  RoleRow,
  SchemaObjectRow,
  SettingRow,
} from "../engine/types";

export async function getVersion(client: Client): Promise<{
  versionString: string;
  serverVersionNum: number;
}> {
  const res = await client.query<{ version: string; version_num: string }>(
    "SELECT version() AS version, current_setting('server_version_num') AS version_num"
  );
  return {
    versionString: res.rows[0]!.version,
    serverVersionNum: parseInt(res.rows[0]!.version_num, 10),
  };
}

export async function getRoles(client: Client): Promise<RoleRow[]> {
  const res = await client.query<{
    rolname: string;
    rolsuper: boolean;
    rolcreaterole: boolean;
    rolcreatedb: boolean;
    rolcanlogin: boolean;
    rolreplication: boolean;
    rolbypassrls: boolean;
    rolvaliduntil: string | null;
  }>(
    `SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin,
            rolreplication, rolbypassrls, rolvaliduntil::text
     FROM pg_roles
     WHERE rolname NOT LIKE 'pg\\_%'
     ORDER BY rolname`
  );
  return res.rows.map((r) => ({
    rolname: r.rolname,
    rolsuper: r.rolsuper,
    rolcreaterole: r.rolcreaterole,
    rolcreatedb: r.rolcreatedb,
    rolcanlogin: r.rolcanlogin,
    rolreplication: r.rolreplication,
    rolbypassrls: r.rolbypassrls,
    rolvaliduntil: r.rolvaliduntil,
  }));
}

/**
 * Grants to PUBLIC on user relations (tables/views/sequences) and CREATE on
 * user schemas. Functions are skipped in v1 (EXECUTE-on-PUBLIC is the default
 * and would be pure noise).
 */
export async function getPublicGrants(client: Client): Promise<PublicGrantRow[]> {
  const relRes = await client.query<{
    schema_name: string;
    object_name: string;
    relkind: string;
    privilege_type: string;
  }>(
    `SELECT n.nspname AS schema_name, c.relname AS object_name, c.relkind::text AS relkind,
            a.privilege_type
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) AS a
     JOIN pg_roles g ON g.oid = a.grantee
     WHERE g.rolname = 'public'
       AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND n.nspname NOT LIKE 'pg\\_%'
     ORDER BY n.nspname, c.relname, a.privilege_type`
  );

  const schemaRes = await client.query<{
    schema_name: string;
    privilege_type: string;
  }>(
    `SELECT n.nspname AS schema_name, a.privilege_type
     FROM pg_namespace n
     CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) AS a
     JOIN pg_roles g ON g.oid = a.grantee
     WHERE g.rolname = 'public'
       AND a.privilege_type IN ('CREATE', 'USAGE')
       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND n.nspname NOT LIKE 'pg\\_%'
     ORDER BY n.nspname, a.privilege_type`
  );

  const grants: PublicGrantRow[] = relRes.rows.map((r) => ({
    objectType: "relation",
    schemaName: r.schema_name,
    objectName: r.object_name,
    relkind: r.relkind,
    privilegeType: r.privilege_type,
  }));
  for (const r of schemaRes.rows) {
    grants.push({
      objectType: "schema",
      schemaName: r.schema_name,
      objectName: r.schema_name,
      relkind: null,
      privilegeType: r.privilege_type,
    });
  }
  return grants;
}

const SETTINGS_OF_INTEREST = [
  "ssl",
  "ssl_min_protocol_version",
  "log_connections",
  "log_disconnections",
  "log_statement",
  "log_min_duration_statement",
  "password_encryption",
];

export async function getSettings(client: Client): Promise<SettingRow[]> {
  const res = await client.query<{
    name: string;
    setting: string;
    unit: string | null;
  }>(
    `SELECT name, setting, unit
     FROM pg_settings
     WHERE name = ANY($1::text[])
     ORDER BY name`,
    [SETTINGS_OF_INTEREST]
  );
  return res.rows.map((r) => ({ name: r.name, setting: r.setting, unit: r.unit }));
}

export async function getSchemaObjects(client: Client): Promise<SchemaObjectRow[]> {
  const res = await client.query<{
    schema_name: string;
    table_name: string;
    relkind: string;
    rls_enabled: boolean;
    rls_forced: boolean;
    column_name: string | null;
    data_type: string | null;
  }>(
    `SELECT n.nspname AS schema_name, c.relname AS table_name, c.relkind::text AS relkind,
            c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS rls_forced,
            a.attname AS column_name, format_type(a.atttypid, a.atttypmod) AS data_type
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     LEFT JOIN pg_attribute a
            ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
     WHERE c.relkind IN ('r', 'p')
       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND n.nspname NOT LIKE 'pg\\_%'
     ORDER BY n.nspname, c.relname, a.attnum`
  );
  return res.rows.map((r) => ({
    schemaName: r.schema_name,
    tableName: r.table_name,
    relkind: r.relkind,
    rlsEnabled: r.rls_enabled,
    rlsForced: r.rls_forced,
    columnName: r.column_name,
    dataType: r.data_type,
  }));
}

export async function introspect(
  client: Client,
  connectionSsl: boolean
): Promise<RawData> {
  const version = await getVersion(client);
  const [roles, publicGrants, settings, schemaObjects] = await Promise.all([
    getRoles(client),
    getPublicGrants(client),
    getSettings(client),
    getSchemaObjects(client),
  ]);
  return {
    ...version,
    roles,
    publicGrants,
    settings,
    schemaObjects,
    connectionSsl,
  };
}
