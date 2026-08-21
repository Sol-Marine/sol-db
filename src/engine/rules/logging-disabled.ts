import { FindingDraft, RawData, Rule } from "../types";

export const loggingDisabled: Rule = {
  id: "logging-disabled",
  run: (data: RawData): FindingDraft[] => {
    const findings: FindingDraft[] = [];

    const check = (
      name: string,
      badValues: string[],
      title: string,
      why: string,
      fix: string,
      severity: "low" | "medium"
    ) => {
      const setting = data.settings.find((s) => s.name === name);
      if (setting && badValues.includes(setting.setting)) {
        findings.push({
          id: `logging-disabled/${name}`,
          title,
          severity,
          category: "configuration",
          description: why,
          evidence: { [name]: setting.setting },
          recommendation: fix,
        });
      }
    };

    check(
      "log_connections",
      ["off"],
      "Failed/successful logins are not logged (log_connections=off)",
      "Without connection logging you cannot detect brute-force attempts or review who connected when — critical for incident response.",
      "Set log_connections = on. On managed providers this may be controlled via provider dashboards.",
      "medium"
    );

    check(
      "log_disconnections",
      ["off"],
      "Session ends are not logged (log_disconnections=off)",
      "Disconnection logging helps compute session durations and spot abnormal patterns during investigations.",
      "Set log_disconnections = on (optional, pairs with log_connections).",
      "low"
    );

    check(
      "log_statement",
      ["none"],
      "Statement logging is fully off (log_statement=none)",
      "No SQL statements are recorded, limiting forensic ability after a suspected breach. Note: 'all' is too noisy for production; targeted logging is usually the right trade-off.",
      "Consider log_statement = 'ddl' or 'mod' for a useful middle ground; use pgaudit for full auditing needs.",
      "low"
    );

    return findings;
  },
};
