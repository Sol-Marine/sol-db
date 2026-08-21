import { Finding, FindingDraft, RawData, Rule } from "./types";

export const RULES: Rule[] = [];

export function registerRule(rule: Rule): void {
  if (RULES.some((r) => r.id === rule.id)) {
    throw new Error(`Rule with id "${rule.id}" is already registered.`);
  }
  RULES.push(rule);
}

export async function runRules(
  data: RawData,
  ctx: Parameters<Rule["run"]>[1]
): Promise<Finding[]> {
  const detectedAt = new Date().toISOString();
  const findings: Finding[] = [];

  for (const rule of RULES) {
    try {
      const drafts: FindingDraft[] = await rule.run(data, ctx);
      for (const draft of drafts) {
        findings.push({ ...draft, detectedAt });
      }
    } catch (err) {
      // A broken rule must never kill the whole audit — record it as an info finding.
      findings.push({
        id: `rule-error/${rule.id}`,
        title: `Rule "${rule.id}" failed to execute`,
        severity: "info",
        category: "configuration",
        description: `The rule threw an error and was skipped: ${
          err instanceof Error ? err.message : String(err)
        }`,
        evidence: {},
        recommendation: "Check sol-db version / server compatibility for this check.",
        detectedAt,
      });
    }
  }

  return findings;
}
