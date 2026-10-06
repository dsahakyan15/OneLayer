import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const reportTool = resolve(repoRoot, "deploy/devnet-demo/scripts/release-report.mjs");
const requiredCheckIds = [
  "runtime-init",
  "preflight",
  "pilot-pipeline",
  "snapshot-package",
  "incident-index",
  "demo-api-tests",
  "verifier-tests",
  "verifier-typecheck",
  "onchain-client-drift",
  "mvp-web-typecheck",
  "mvp-web-build",
  "browser-e2e",
  "backup-recovery-e2e",
];

async function writeJson(file: string, value: unknown): Promise<void> {
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function check(evidenceDir: string, id: string, status: "PASS" | "FAIL"): Promise<void> {
  await mkdir(resolve(evidenceDir, "checks"), { recursive: true });
  const log = id === "incident-index"
    ? "an opened incident becomes an OPEN notice\na resolve event clears the current status\nan interrupted scan keeps the old watermark"
    : id === "backup-recovery-e2e"
      ? "bootstraps five centers, adds a sixth, and replicates one immutable snapshot\nshows partial success and retries the same pending replica\nretention keeps twelve folders and preserves the finalized snapshot\nrecovery rejects two shares before creating an approval operation\nciphertext and root failures stop recovery before Restore Approval\nthree shares wait for chief approval, preserve the binding, and restore the full state"
    : id === "verifier-tests" ? "stale watermark cannot produce VERIFIED" : `${id} passed`;
  await writeFile(resolve(evidenceDir, "checks", `${id}.log`), `${log}\n`, "utf8");
  await writeJson(resolve(evidenceDir, "checks", `${id}.json`), {
    id,
    status,
    exit_code: status === "PASS" ? 0 : 1,
    log: `checks/${id}.log`,
    ...(status === "FAIL" ? { remediation: [`remediate ${id}`] } : {}),
  });
}

async function writePlaywrightArtifacts(evidenceDir: string): Promise<void> {
  for (const directory of ["browser-playwright-report", "browser-test-results", "backup-playwright-report", "backup-test-results"]) {
    await mkdir(resolve(evidenceDir, directory), { recursive: true });
    if (directory.endsWith("test-results")) {
      await writeFile(resolve(evidenceDir, directory, "trace.zip"), "trace", "utf8");
      await writeFile(resolve(evidenceDir, directory, "screenshot.png"), "screenshot", "utf8");
    }
  }
}

async function writeSoakEvidence(evidenceDir: string): Promise<void> {
  const records = Array.from({ length: 73 }, (_, index) => ({
    cycle: index + 1,
    finalized_at: 1_800_000_000 + index * 3_600,
    batch_sequence: index + 1,
    anchor_slot: 400_000_000 + index,
    manual_intervention: false,
    incident_index_status: "CHECKED",
    source_cursor_start: 1,
    source_cursor_end: 2,
    rebuilt_source_cursor_start: 1,
    rebuilt_source_cursor_end: 2,
    manifest_hash: `manifest-${index + 1}`,
    rebuilt_manifest_hash: `manifest-${index + 1}`,
  }));
  await writeFile(resolve(evidenceDir, "soak.jsonl"), `${records.map((record) => JSON.stringify(record)).join("\n")}\n`, "utf8");
}

async function completeEvidence(): Promise<string> {
  const root = await mkdtemp(resolve(tmpdir(), "onelayer-gate-c-"));
  const evidenceDir = resolve(root, "gate-c");
  await mkdir(evidenceDir, { recursive: true });
  await writeSoakEvidence(evidenceDir);
  await writeJson(resolve(evidenceDir, "soak-report.json"), {
    verdict: "Passed",
    cycles: 73,
    observed_seconds: 259200,
    anchor_sequence_gap_total: 0,
    manifest_rebuild_checks: 73,
    manifest_rebuild_mismatch_total: 0,
    source_range_checks: 73,
    source_range_mismatch_total: 0,
    incident_index_not_checked_total: 0,
    findings: [],
  });
  for (const id of requiredCheckIds) {
    await check(evidenceDir, id, "PASS");
  }
  await writePlaywrightArtifacts(evidenceDir);
  const certificatePackageHash = "09".repeat(32);
  const qrHash = Buffer.from(certificatePackageHash, "hex").toString("base64url");
  await writeJson(resolve(root, "live-smoke/evidence.json"), {
    schema: "onelayer.gate-c.live-smoke.v1",
    status: "PASS",
    classification: "BOUNDED_SYNTHETIC_MVP",
    separate_approval: true,
    finalized_anchor: true,
    key_material_in_browser: false,
    certificate_id: "08".repeat(16),
    certificate_package_hash: certificatePackageHash,
    transaction_signature: "signature",
    anchor_slot: 42,
    qr_hash: qrHash,
    qr_url: `http://127.0.0.1:8091/c/08080808080808080808080808080808?h=${qrHash}`,
    artifacts: ["verified.png", "trace.zip"],
  });
  await writeFile(resolve(root, "live-smoke/verified.png"), "screenshot", "utf8");
  await writeFile(resolve(root, "live-smoke/trace.zip"), "trace", "utf8");
  return evidenceDir;
}

test("renders a PASS report only when all Gate C evidence is present", async () => {
  const evidenceDir = await completeEvidence();
  await execFileAsync("node", [reportTool, "render", evidenceDir], { cwd: repoRoot });
  const report = JSON.parse(await readFile(resolve(evidenceDir, "release-report.json"), "utf8"));
  assert.equal(report.verdict, "PASS");
  assert.equal(report.classification, "BOUNDED_SYNTHETIC_MVP");
  assert.equal(report.acceptance.every((item: { status: string }) => item.status === "PASS"), true);
  assert.match(report.acceptance.find((item: { id: string }) => item.id === "GATE-C-BROWSER").evidence.join(" "), /browser-playwright-report/);
  assert.match(report.acceptance.find((item: { id: string }) => item.id === "GATE-C-BACKUP").evidence.join(" "), /backup-playwright-report/);
  assert.match(report.scope.exclusions.join(" "), /geographically independent/);
  assert.match(report.scope.exclusions.join(" "), /release gate 7/);
});

test("missing live evidence is INCOMPLETE rather than a false release pass", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "onelayer-gate-c-incomplete-"));
  const evidenceDir = resolve(root, "gate-c");
  await mkdir(evidenceDir, { recursive: true });
  await writeSoakEvidence(evidenceDir);
  await writeJson(resolve(evidenceDir, "soak-report.json"), {
    verdict: "Passed",
    cycles: 73,
    observed_seconds: 259200,
    anchor_sequence_gap_total: 0,
    manifest_rebuild_checks: 73,
    manifest_rebuild_mismatch_total: 0,
    source_range_checks: 73,
    source_range_mismatch_total: 0,
    incident_index_not_checked_total: 0,
    findings: [],
  });
  for (const id of requiredCheckIds) {
    await check(evidenceDir, id, "PASS");
  }
  await writePlaywrightArtifacts(evidenceDir);
  await assert.rejects(
    execFileAsync("node", [reportTool, "render", evidenceDir], { cwd: repoRoot }),
    (error: unknown) => (error as { code?: number }).code === 3,
  );
  const report = JSON.parse(await readFile(resolve(evidenceDir, "release-report.json"), "utf8"));
  assert.equal(report.verdict, "INCOMPLETE");
  assert.equal(report.acceptance.find((item: { id: string }) => item.id === "GATE-C-LIVE").status, "NOT_RUN");
});

test("a sparse soak JSONL cannot satisfy the 72-hour report", async () => {
  const evidenceDir = await completeEvidence();
  await writeFile(resolve(evidenceDir, "soak.jsonl"), [
    JSON.stringify({ cycle: 1, finalized_at: 1_800_000_000 }),
    JSON.stringify({ cycle: 73, finalized_at: 1_800_259_200 }),
  ].join("\n"), "utf8");
  await assert.rejects(
    execFileAsync("node", [reportTool, "render", evidenceDir], { cwd: repoRoot }),
    (error: unknown) => (error as { code?: number }).code === 2,
  );
  const report = JSON.parse(await readFile(resolve(evidenceDir, "release-report.json"), "utf8"));
  assert.equal(report.verdict, "FAIL");
  assert.equal(report.acceptance.find((item: { id: string }) => item.id === "GATE-C-SOAK").status, "FAIL");
});

test("failed preflight remains FAIL and carries remediation", async () => {
  const evidenceDir = await completeEvidence();
  await check(evidenceDir, "preflight", "FAIL");
  await assert.rejects(
    execFileAsync("node", [reportTool, "render", evidenceDir], { cwd: repoRoot }),
    (error: unknown) => (error as { code?: number }).code === 2,
  );
  const report = JSON.parse(await readFile(resolve(evidenceDir, "release-report.json"), "utf8"));
  assert.equal(report.verdict, "FAIL");
  assert.match(report.remediation.join(" "), /remediate preflight/);
});
