#!/usr/bin/env node
import { Command } from "commander";
import * as fs from "fs";
import * as path from "path";
import { config, ensureDirs } from "./config";
import { connect, disconnect } from "./db/connect";
import { introspect } from "./db/introspect";
import { FindingsStore } from "./db/store";
import { runRules } from "./engine/runner";
import { registerAllRules } from "./engine/rules";
import { buildSnapshot, diffSnapshots } from "./engine/rules/schema-diff";
import { SchemaSnapshot } from "./engine/types";
import { renderReport, reportFileName } from "./report/markdown";

const program = new Command();

program
  .name("sol-db")
  .description("Read-only Postgres security auditor for databases you own")
  .version("0.1.0");

function resolveTarget(explicit?: string): string {
  if (explicit) return explicit;
  if (process.env.SOL_DB_DEFAULT_TARGET) return process.env.SOL_DB_DEFAULT_TARGET;
  try {
    const host = new URL(config.dbUrl).hostname;
    if (host) return host;
  } catch {
    // fall through
  }
  return "default";
}

program
  .command("run")
  .description("Run a full audit: introspect, analyze, persist, write a Markdown report")
  .option("-t, --target <label>", "label for this target (defaults to db host)")
  .action(async (opts: { target?: string }) => {
    ensureDirs();
    registerAllRules();
    const targetLabel = resolveTarget(opts.target);
    const startedAt = new Date().toISOString();

    console.log(`[sol-db] auditing target "${targetLabel}"...`);
    const store = new FindingsStore(config.dataDir);
    const runId = store.createRun(targetLabel, startedAt);

    let client;
    try {
      const info = await connect(config.dbUrl);
      client = info.client;
      console.log(
        `[sol-db] connected as "${info.currentUser}" (TLS: ${info.sslUsed ? "yes" : "no"}), read-only verified`
      );

      const data = await introspect(client, info.sslUsed);
      console.log(
        `[sol-db] introspected: ${data.roles.length} roles, ${data.publicGrants.length} PUBLIC grants, ${new Set(
          data.schemaObjects.map((o) => `${o.schemaName}.${o.tableName}`)
        ).size} tables`
      );

      const previous = store.getLatestRunWithSnapshot(targetLabel);
      const currentSnapshot = buildSnapshot(
        data.schemaObjects,
        data.publicGrants,
        startedAt
      );

      const findings = await runRules(data, {
        previousSnapshot: previous?.snapshot ?? null,
        currentSnapshot,
      });

      store.saveFindings(runId, findings);
      store.saveSnapshot(runId, currentSnapshot);
      store.finishRun(runId, new Date().toISOString(), data.versionString);

      const report = renderReport({
        targetLabel,
        startedAt,
        pgVersion: data.versionString,
        findings,
        comparedToRunId: previous?.runId ?? null,
      });
      const reportPath = path.join(
        config.reportsDir,
        reportFileName(targetLabel, startedAt)
      );
      fs.writeFileSync(reportPath, report, "utf8");

      const bySeverity = (sev: string) =>
        findings.filter((f) => f.severity === sev).length;
      console.log("");
      console.log(
        `[sol-db] done — ${findings.length} finding(s): ` +
          `${bySeverity("critical")} critical / ${bySeverity("high")} high / ` +
          `${bySeverity("medium")} medium / ${bySeverity("low")} low / ${bySeverity("info")} info`
      );
      console.log(`[sol-db] report written to ${reportPath}`);
    } catch (err) {
      store.finishRun(runId, new Date().toISOString(), "aborted");
      console.error(`[sol-db] ERROR: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    } finally {
      store.close();
      if (client) await disconnect(client);
    }
  });

program
  .command("history")
  .description("List past runs and severity counts for a target")
  .option("-t, --target <label>", "target label (defaults to all targets)")
  .action((opts: { target?: string }) => {
    ensureDirs();
    const store = new FindingsStore(config.dataDir);
    try {
      const runs = store.listRuns(opts.target);
      if (runs.length === 0) {
        console.log("No runs recorded yet. Start with: sol-db run --target <label>");
        return;
      }
      for (const r of runs) {
        const c = r.counts;
        console.log(
          `#${r.id}  ${r.targetLabel.padEnd(20)} ${r.startedAt}  ` +
            `pg:${r.pgVersion ? r.pgVersion.split(" ")[1] ?? "?" : "?"}  ` +
            `C:${c.critical} H:${c.high} M:${c.medium} L:${c.low} I:${c.info}`
        );
      }
    } finally {
      store.close();
    }
  });

program
  .command("diff")
  .description("Show schema/config drift since the last stored run (nothing is saved)")
  .option("-t, --target <label>", "label for this target (defaults to db host)")
  .action(async (opts: { target?: string }) => {
    ensureDirs();
    registerAllRules();
    const targetLabel = resolveTarget(opts.target);
    const store = new FindingsStore(config.dataDir);

    let client;
    try {
      const previous = store.getLatestRunWithSnapshot(targetLabel);
      if (!previous) {
        console.log(
          `No previous snapshot for "${targetLabel}". Run \`sol-db run --target ${targetLabel}\` first.`
        );
        return;
      }

      const info = await connect(config.dbUrl);
      client = info.client;
      const data = await introspect(client, info.sslUsed);
      const currentSnapshot: SchemaSnapshot = buildSnapshot(
        data.schemaObjects,
        data.publicGrants,
        new Date().toISOString()
      );

      const drift = diffSnapshots(previous.snapshot, currentSnapshot);

      if (drift.length === 0) {
        console.log(`No drift detected since run #${previous.runId}.`);
        return;
      }
      console.log(`Drift since run #${previous.runId} (${previous.snapshot.capturedAt}):`);
      console.log("");
      for (const d of drift) {
        console.log(`[${d.severity.toUpperCase()}] ${d.title}`);
        console.log(JSON.stringify(d.evidence, null, 2));
        console.log("");
      }
    } catch (err) {
      console.error(`[sol-db] ERROR: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    } finally {
      store.close();
      if (client) await disconnect(client);
    }
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(`[sol-db] ERROR: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
