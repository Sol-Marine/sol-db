import { Client, QueryResult } from "pg";

export class ReadOnlyViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReadOnlyViolationError";
  }
}

export interface ConnectionInfo {
  client: Client;
  sslUsed: boolean;
  currentUser: string;
  serverVersion: string;
}

function isLocalHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host.endsWith(".sock");
}

export function parseSslMode(url: string): string | null {
  const match = /[?&]sslmode=([^&]+)/.exec(url);
  return match && match[1] ? match[1] : null;
}

export async function connect(dbUrl: string): Promise<ConnectionInfo> {
  if (!dbUrl) {
    throw new Error(
      "AUDIT_DB_URL is not set. Copy .env.example to .env and provide a read-only role's connection string."
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(dbUrl);
  } catch {
    throw new Error("AUDIT_DB_URL is not a valid connection string.");
  }
  const host = parsed.hostname;
  const sslMode = parseSslMode(dbUrl);

  if (sslMode === "disable" && !isLocalHost(host)) {
    throw new Error(
      `Refusing to connect to non-local host "${host}" with sslmode=disable. TLS is required.`
    );
  }

  const sslRequired = !isLocalHost(host);
  const client = new Client({
    connectionString: dbUrl,
    ssl: sslRequired ? { rejectUnauthorized: false } : undefined,
  });

  await client.connect();

  // Verify the connection is actually encrypted when we required it.
  let sslUsed = false;
  try {
    const res = await client.query<{ ssl: boolean | null }>(
      "SELECT pg_ssl_is_used() AS ssl"
    );
    sslUsed = res.rows[0]?.ssl === true;
  } catch {
    // pg_ssl_is_used() exists on PG 9.5+; fall back to assuming per config.
    sslUsed = sslRequired;
  }
  if (sslRequired && !sslUsed) {
    await client.end();
    throw new Error("TLS was required but the connection is not encrypted. Aborting.");
  }

  const who = await client.query<{ current_user: string; version: string }>(
    "SELECT current_user, version()"
  );
  const currentUser = who.rows[0]!.current_user;
  const serverVersion = who.rows[0]!.version;

  await assertReadOnly(client, currentUser);

  // Belt and braces: make every subsequent transaction read-only for this session.
  await client.query("SET default_transaction_read_only = on");

  return { client, sslUsed, currentUser, serverVersion };
}

async function assertReadOnly(client: Client, currentUser: string): Promise<void> {
  const superRes = await client.query<{ rolsuper: boolean }>(
    "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
  );
  if (superRes.rows[0]?.rolsuper) {
    throw new ReadOnlyViolationError(
      `Connected role "${currentUser}" is a SUPERUSER. Create a dedicated least-privilege role instead — never audit with admin credentials.`
    );
  }

  const writeRes: QueryResult<{
    schema_name: string;
    table_name: string;
    can_insert: boolean;
    can_update: boolean;
    can_delete: boolean;
  }> = await client.query(
    `SELECT n.nspname AS schema_name, c.relname AS table_name,
            has_table_privilege(current_user, c.oid, 'INSERT') AS can_insert,
            has_table_privilege(current_user, c.oid, 'UPDATE') AS can_update,
            has_table_privilege(current_user, c.oid, 'DELETE') AS can_delete
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind IN ('r', 'p')
       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND n.nspname NOT LIKE 'pg\\_%'`
  );

  const writable = writeRes.rows.filter(
    (r) => r.can_insert || r.can_update || r.can_delete
  );

  if (writable.length > 0) {
    const list = writable
      .slice(0, 10)
      .map((r) => `${r.schema_name}.${r.table_name}`)
      .join(", ");
    const more = writable.length > 10 ? ` (+${writable.length - 10} more)` : "";
    throw new ReadOnlyViolationError(
      `Connected role "${currentUser}" has write privileges on ${writable.length} non-system table(s): ${list}${more}. ` +
        "Revoke INSERT/UPDATE/DELETE from the audit role before running sol-db."
    );
  }
}

export async function disconnect(client: Client): Promise<void> {
  try {
    await client.end();
  } catch {
    // ignore double-close
  }
}
