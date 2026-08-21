import { FindingDraft, RawData, Rule } from "../types";

export interface EolEntry {
  cycle: string | number;
  latest: string;
  releaseDate: string | null;
  eol: string | false;
  support: string | false;
}

export function parseVersion(versionString: string): {
  major: number;
  minor: number;
  patch: number;
} | null {
  // e.g. "PostgreSQL 16.3 (Debian ...)" or "PostgreSQL 15.7 on x86_64..."
  const m = /PostgreSQL\s+(\d+)\.(\d+)(?:\.(\d+))?/.exec(versionString);
  if (!m) return null;
  return {
    major: parseInt(m[1]!, 10),
    minor: parseInt(m[2]!, 10),
    patch: m[3] ? parseInt(m[3], 10) : 0,
  };
}

export function assessVersion(
  parsed: { major: number; minor: number; patch: number },
  eolData: EolEntry[]
): FindingDraft[] {
  const findings: FindingDraft[] = [];
  const entry = eolData.find((e) => String(e.cycle) === String(parsed.major));

  if (!entry) {
    findings.push({
      id: "outdated-version/major-unknown",
      title: `Major version ${parsed.major} not found in upstream lifecycle data`,
      severity: "high",
      category: "configuration",
      description: `Server reports PostgreSQL ${parsed.major}.${parsed.minor}.${parsed.patch}. This major version is absent from endoflife.date records — likely very old and unsupported.`,
      evidence: { running: `${parsed.major}.${parsed.minor}.${parsed.patch}` },
      recommendation: "Plan an upgrade to a supported major version immediately.",
    });
    return findings;
  }

  const isEol = typeof entry.eol === "string"; // eol date already passed per API
  if (isEol) {
    findings.push({
      id: "outdated-version/eol-major",
      title: `PostgreSQL ${entry.cycle} is end-of-life`,
      severity: "critical",
      category: "configuration",
      description: `PostgreSQL ${entry.cycle} reached end of life${entry.eol ? ` on ${entry.eol}` : ""}. It no longer receives security fixes. Known and future CVEs will remain unpatched.`,
      evidence: {
        running: `${parsed.major}.${parsed.minor}.${parsed.patch}`,
        cycleEol: entry.eol,
      },
      recommendation: `Upgrade to a supported major version (${eolData
        .filter((e) => typeof e.eol !== "string")
        .map((e) => e.cycle)
        .join(", ")}) and plan migration testing.`,
    });
    return findings;
  }

  const latestParts = entry.latest.split(".").map((x) => parseInt(x, 10));
  const latestMinor = latestParts[1] ?? 0;
  const latestPatch = latestParts[2] ?? 0;
  const behind =
    parsed.minor < latestMinor ||
    (parsed.minor === latestMinor && parsed.patch < latestPatch);
  if (behind) {
    findings.push({
      id: "outdated-version/minor-behind",
      title: `Running ${parsed.major}.${parsed.minor}.${parsed.patch}, latest is ${entry.latest}`,
      severity: "low",
      category: "configuration",
      description:
        "Your minor version is behind the latest cumulative update. Postgres minor releases regularly include security fixes; falling behind leaves you exposed to patched CVEs.",
      evidence: {
        running: `${parsed.major}.${parsed.minor}.${parsed.patch}`,
        latest: entry.latest,
      },
      recommendation: `Schedule an update to ${entry.latest} (minor upgrades are in-place compatible).`,
    });
  }

  return findings;
}

async function fetchEolData(): Promise<EolEntry[] | null> {
  try {
    const res = await fetch("https://endoflife.date/api/postgresql.json", {
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;
    return (await res.json()) as EolEntry[];
  } catch {
    return null;
  }
}

export const outdatedVersion: Rule = {
  id: "outdated-version",
  run: async (data: RawData): Promise<FindingDraft[]> => {
    const parsed = parseVersion(data.versionString);
    if (!parsed) return [];

    const eolData = await fetchEolData();
    if (!eolData) {
      return [
        {
          id: "outdated-version/check-unavailable",
          title: "Could not verify version currency",
          severity: "info",
          category: "configuration",
          description: `Server reports PostgreSQL ${parsed.major}.${parsed.minor}.${parsed.patch}, but the endoflife.date lookup failed (offline or blocked). No EOL assessment was made.`,
          evidence: { versionString: data.versionString },
          recommendation:
            "Manually confirm your major version is supported at https://endoflife.date/postgresql.",
        },
      ];
    }

    return assessVersion(parsed, eolData);
  },
};
