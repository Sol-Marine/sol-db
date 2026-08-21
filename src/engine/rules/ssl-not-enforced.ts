import { FindingDraft, RawData, Rule } from "../types";

export const sslNotEnforced: Rule = {
  id: "ssl-not-enforced",
  run: (data: RawData): FindingDraft[] => {
    const findings: FindingDraft[] = [];
    const sslSetting = data.settings.find((s) => s.name === "ssl");
    const minProto = data.settings.find((s) => s.name === "ssl_min_protocol_version");

    if (sslSetting && sslSetting.setting === "off") {
      findings.push({
        id: "ssl-not-enforced/server-off",
        title: "Server has SSL disabled",
        severity: "critical",
        category: "configuration",
        description:
          "ssl=off means every client connection to this database travels unencrypted, including credentials during login.",
        evidence: { ssl: sslSetting.setting },
        recommendation:
          "Set ssl=on, configure server certificates, and require TLS on all clients (hostssl rules in pg_hba.conf). Managed providers usually enforce this already.",
      });
    }

    if (!data.connectionSsl) {
      findings.push({
        id: "ssl-not-enforced/unencrypted-connection",
        title: "This audit connection is not encrypted",
        severity: "high",
        category: "configuration",
        description:
          "sol-db connected without TLS (local socket or explicit non-TLS config). Fine for localhost audits, but confirm remote clients are not doing the same.",
        evidence: { connectionSsl: false },
        recommendation:
          "Require sslmode=require (or verify-full) in connection strings used outside localhost.",
      });
    }

    if (minProto) {
      const v = minProto.setting;
      const weak =
        v === "" ||
        /^(TLSv)?1(\.0|\.1)?$/.test(v) ||
        v.toLowerCase() === "tlsv1" ||
        v.toLowerCase() === "tlsv1_1";
      if (weak) {
        findings.push({
          id: "ssl-not-enforced/weak-min-tls",
          title: `Weak minimum TLS version: ${v || "(unset)"}`,
          severity: "medium",
          category: "configuration",
          description:
            "ssl_min_protocol_version allows legacy TLS 1.0/1.1, which are deprecated and vulnerable to known attacks.",
          evidence: { ssl_min_protocol_version: v },
          recommendation: "Set ssl_min_protocol_version = 'TLSv1.2' (or 'TLSv1.3').",
        });
      }
    }

    return findings;
  },
};
