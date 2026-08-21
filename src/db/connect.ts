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

  // Lock the session down BEFORE any privilege analysis: from here on the
  // server itself rejects writes, whatever the role's privileges say.
  await client.query("SET default_transaction_read_only = on");

  try {
    await assertReadOnly(client, currentUser);
  } catch (err) {
    await client.end().catch(() => {});
    throw err;
  }

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
    public_insert: boolean;
    public_update: boolean;
    public_delete: boolean;
  }> = await client.query(
    `SELECT n.nspname AS schema_name, c.relname AS table_name,
            has_table_privilege(current_user, c.oid, 'INSERT') AS can_insert,
            has_table_privilege(current_user, c.oid, 'UPDATE') AS can_update,
            has_table_privilege(current_user, c.oid, 'DELETE') AS can_delete,
            has_table_privilege('public', c.oid, 'INSERT') AS public_insert,
            has_table_privilege('public', c.oid, 'UPDATE') AS public_update,
            has_table_privilege('public', c.oid, 'DELETE') AS public_delete
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind IN ('r', 'p')
       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND n.nspname NOT LIKE 'pg\\_%'`
  );

  const directWritable = writeRes.rows.filter(
    (r) =>
      (r.can_insert && !r.public_insert) ||
      (r.can_update && !r.public_update) ||
      (r.can_delete && !r.public_delete)
  );

  if (directWritable.length > 0) {
    const list = directWritable
      .slice(0, 10)
      .map((r) => `${r.schema_name}.${r.table_name}`)
      .join(", ");
    const more =
      directWritable.length > 10 ? ` (+${directWritable.length - 10} more)` : "";
    throw new ReadOnlyViolationError(
      `Connected role "${currentUser}" holds direct write privileges on ${directWritable.length} non-system table(s): ${list}${more}. ` +
        "Revoke INSERT/UPDATE/DELETE from the audit role before running sol-db."
    );
  }

  // Write access inherited purely via PUBLIC means the TARGET is insecure
  // (the rules below will report it) - not that the audit setup is wrong.
  // The session is already pinned read-only, so proceeding is safe.
  const publicOnly = writeRes.rows.filter(
    (r) => r.can_insert || r.can_update || r.can_delete
  );
  if (publicOnly.length > 0) {
    console.warn(
      `[sol-db] WARNING: audit role inherits write privileges via PUBLIC on ${publicOnly.length} table(s). ` +
        "That is a finding about the target, not this tool - session is enforced read-only."
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
