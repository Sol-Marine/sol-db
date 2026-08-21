import * as path from "path";
import * as fs from "fs";
import * as dotenv from "dotenv";

const projectRoot = path.resolve(__dirname, "..", "..");

dotenv.config({ path: path.join(projectRoot, ".env") });

function parsePatternList(name: string, fallback: string[]): string[] {
  const raw = process.env[name];
  if (!raw) return fallback;
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export const config = {
  projectRoot,
  dataDir: process.env.SOL_DB_DATA_DIR ?? path.join(projectRoot, "data"),
  reportsDir: process.env.SOL_DB_REPORTS_DIR ?? path.join(projectRoot, "reports"),
  dbUrl: process.env.AUDIT_DB_URL ?? "",
  sensitiveTablePatterns: parsePatternList("SENSITIVE_TABLE_PATTERNS", [
    "user",
    "email",
    "payment",
    "token",
    "password",
    "secret",
    "credential",
    "session",
    "api_key",
  ]),
  secretColumnPatterns: parsePatternList("SECRET_COLUMN_PATTERNS", [
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "credential",
    "private_key",
  ]),
};

export function ensureDirs(): void {
  for (const dir of [config.dataDir, config.reportsDir]) {
    fs.mkdirSync(dir, { recursive: true });
  }
}
