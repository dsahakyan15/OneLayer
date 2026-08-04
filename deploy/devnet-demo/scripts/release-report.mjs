#!/usr/bin/env node

/**
 * Build the machine-readable and human-readable Gate C evidence report.
 *
 * This helper deliberately has no third-party dependencies. The shell runner
 * records command outcomes with `record`; `render` only reads those outcomes
 * and the evidence artifacts, so rebuilding a report never re-runs a test or
 * spends devnet SOL.
 */

import { readdir, readFile, rename, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const demoDir = resolve(here, "..");
const defaultEvidenceDir = resolve(demoDir, "artifacts/gate-c");

const REMEDIATIONS = {
  preflight: [
    "Read checks/preflight.log and correct the first failed dependency.",
    "Re-run deploy/devnet-demo/scripts/initialize-runtime and preflight after remediation.",
    "Do not run a mutating publish or recovery step while preflight is failing.",
  ],
  "incident-index": [
    "Inspect the incident-index test log and repair finalized event or watermark handling.",
    "Re-run the focused incident-index tests before collecting a new release report.",
  ],
  "verifier-tests": [
    "Inspect the verifier test log and confirm stale or unavailable indexes return VERIFIED_NO_INCIDENT_CHECK.",
  ],
  "browser-e2e": [
    "Open the Playwright report and retained trace/screenshot for the failed scenario.",
    "Fix the deterministic fixture flow, then rerun the browser suite in a fresh context.",
  ],
  "backup-recovery-e2e": [
    "Open the Playwright report and identify the failed backup/recovery branch.",
    "Verify the failure is fail-closed before collecting a new release report.",
  ],
  "live-smoke": [
    "Keep the separate live-smoke approval unset until the devnet preflight and approval digests are ready.",
    "If the smoke was approved, inspect deploy/devnet-demo/artifacts/live-smoke for its trace and screenshot.",
  ],
};

const EXCLUSIONS = [
  "This is bounded synthetic MVP evidence on Solana devnet.",
  "It does not claim geographically independent Backup Centers or custodians.",
  "It does not claim a production restore drill or production recovery readiness.",
  "It does not close release gate 7 or any later Monitor/production gate.",
];

const REQUIRED_CHECKS = [
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

function evidenceDirFromArg(value) {
  return resolve(value ?? process.env.ONELAYER_GATE_C_EVIDENCE_DIR ?? defaultEvidenceDir);
}

function relativeArtifact(evidenceDir, file) {
  return relative(evidenceDir, file).split("\\").join("/");
}

async function readJson(file) {
  if (!existsSync(file)) return null;
  return JSON.parse(await readFile(file, "utf8"));
}

async function readText(file) {
  if (!existsSync(file)) return null;
  return readFile(file, "utf8");
}

async function hasFileWithExtension(directory, extension) {
  if (!existsSync(directory)) return false;
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const file = resolve(directory, entry.name);
    if (entry.isDirectory() && await hasFileWithExtension(file, extension)) return true;
    if (entry.isFile() && entry.name.endsWith(extension)) return true;
  }
  return false;
}

async function hasFileWithName(directory, name) {
  if (!existsSync(directory)) return false;
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const file = resolve(directory, entry.name);
    if (entry.isDirectory() && await hasFileWithName(file, name)) return true;
    if (entry.isFile() && entry.name === name) return true;
  }
  return false;
}

async function readJsonLines(file) {
  if (!existsSync(file)) return null;
  const records = [];
  for (const line of (await readFile(file, "utf8")).split(/\r?\n/)) {
    if (line.trim() === "") continue;
    records.push(JSON.parse(line));
  }
  return records;
}

function checkLog(evidenceDir, checks, id) {
  const check = checks.get(id);
  return resolve(evidenceDir, check?.log ?? `checks/${id}.log`);
}

async function writeAtomic(file, content) {
  await mkdir(dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${process.pid}`;
  await writeFile(temporary, content, "utf8");
  await rename(temporary, file);
}

function result(status, evidence, details = {}) {
  return { status, evidence, ...details };
}

function checkStatus(checks, id) {
  return checks.get(id)?.status ?? "NOT_RUN";
}

async function loadChecks(evidenceDir) {
  const checksDir = resolve(evidenceDir, "checks");
  const checks = new Map();
  if (!existsSync(checksDir)) return checks;
  for (const name of await readdir(checksDir)) {
    if (!name.endsWith(".json")) continue;
    const value = await readJson(resolve(checksDir, name));
    if (value?.id) checks.set(value.id, value);
  }
  return checks;
}

async function liveSmokeEvidence(evidenceDir) {
  const configured = process.env.ONELAYER_LIVE_EVIDENCE;
  const file = configured === undefined
    ? resolve(evidenceDir, "../live-smoke/evidence.json")
    : resolve(configured);
  const value = await readJson(file);
  if (value === null) {
    return result("NOT_RUN", [relativeArtifact(evidenceDir, file)], {
      reason: "The separately approved live-devnet smoke has not produced a PASS evidence artifact.",
    });
  }
  if (value.status !== "PASS") {
    return result("FAIL", [relativeArtifact(evidenceDir, file)], {
      reason: "The live-devnet smoke produced a non-PASS evidence artifact.",
      remediation: REMEDIATIONS["live-smoke"],
    });
  }
  const certificateId = typeof value.certificate_id === "string" ? value.certificate_id : "";
  const certificatePackageHash = typeof value.certificate_package_hash === "string" ? value.certificate_package_hash : "";
  const qrUrl = typeof value.qr_url === "string" ? value.qr_url : "";
  const qrHash = typeof value.qr_hash === "string" ? value.qr_hash : "";
  const liveArtifactDir = dirname(file);
  const declaredArtifacts = Array.isArray(value.artifacts) ? value.artifacts : [];
  const valid = value.schema === "onelayer.gate-c.live-smoke.v1"
    && value.classification === "BOUNDED_SYNTHETIC_MVP"
    && value.separate_approval === true
    && value.key_material_in_browser === false
    && value.finalized_anchor === true
    && /^[0-9a-f]{32}$/.test(certificateId)
    && /^[0-9a-f]{64}$/.test(certificatePackageHash)
    && typeof value.transaction_signature === "string"
    && value.transaction_signature.length > 0
    && Number.isSafeInteger(value.anchor_slot)
    && value.anchor_slot > 0
    && /^[A-Za-z0-9_-]+$/.test(qrHash)
    && qrHash === Buffer.from(certificatePackageHash, "hex").toString("base64url")
    && qrUrl.includes(`/c/${certificateId}?h=${qrHash}`)
    && declaredArtifacts.includes("verified.png")
    && declaredArtifacts.includes("trace.zip")
    && await hasFileWithName(liveArtifactDir, "verified.png")
    && await hasFileWithName(liveArtifactDir, "trace.zip");
  if (!valid) {
    return result("FAIL", [relativeArtifact(evidenceDir, file)], {
      reason: "Live evidence does not prove separately approved finalized-anchor use with no browser key material.",
      remediation: REMEDIATIONS["live-smoke"],
    });
  }
  return result("PASS", [relativeArtifact(evidenceDir, file)], {
    details: {
      separateApproval: true,
      certificateId,
      transactionSignature: value.transaction_signature,
      anchorSlot: value.anchor_slot,
      artifacts: ["verified.png", "trace.zip"],
    },
  });
}

async function render(evidenceDir) {
  const checks = await loadChecks(evidenceDir);
  const soakFile = resolve(evidenceDir, "soak-report.json");
  const soakEvidenceFile = resolve(evidenceDir, "soak.jsonl");
  const soak = await readJson(soakFile);
  let soakRecords = null;
  let soakJsonlValid = true;
  try {
    soakRecords = await readJsonLines(soakEvidenceFile);
  } catch {
    soakJsonlValid = false;
  }
  const firstSoakTimestamp = soakRecords?.[0]?.finalized_at;
  const lastSoakTimestamp = soakRecords?.at(-1)?.finalized_at;
  const soakEvidencePass = soakJsonlValid
    && Array.isArray(soakRecords)
    && soakRecords.length >= 73
    && soakRecords.length === soak?.cycles
    && soakRecords.every((record, index) => record.cycle === index + 1
      && Number.isSafeInteger(record.finalized_at)
      && Number.isSafeInteger(record.batch_sequence)
      && Number.isSafeInteger(record.anchor_slot)
      && record.manual_intervention === false
      && record.incident_index_status === "CHECKED"
      && Number.isSafeInteger(record.source_cursor_start)
      && Number.isSafeInteger(record.source_cursor_end)
      && Number.isSafeInteger(record.rebuilt_source_cursor_start)
      && Number.isSafeInteger(record.rebuilt_source_cursor_end)
      && record.source_cursor_start <= record.source_cursor_end
      && record.source_cursor_start === record.rebuilt_source_cursor_start
      && record.source_cursor_end === record.rebuilt_source_cursor_end
      && typeof record.manifest_hash === "string"
      && record.manifest_hash === record.rebuilt_manifest_hash)
    && Number.isSafeInteger(firstSoakTimestamp)
    && Number.isSafeInteger(lastSoakTimestamp)
    && lastSoakTimestamp - firstSoakTimestamp >= 259200;
  const soakPass = soak?.verdict === "Passed"
    && Number.isSafeInteger(soak.cycles)
    && soak.cycles >= 73
    && Number.isSafeInteger(soak.observed_seconds)
    && soak.observed_seconds >= 259200
    && soakEvidencePass
    && soak.manifest_rebuild_checks === soak.cycles
    && soak.source_range_checks === soak.cycles
    && soak.anchor_sequence_gap_total === 0
    && soak.manifest_rebuild_mismatch_total === 0
    && soak.source_range_mismatch_total === 0
    && soak.incident_index_not_checked_total === 0
    && Array.isArray(soak.findings)
    && soak.findings.length === 0;
  const soakResult = soak === null
    ? result("NOT_RUN", [relativeArtifact(evidenceDir, soakFile), relativeArtifact(evidenceDir, soakEvidenceFile)], {
      reason: "No soak report was recorded.",
    })
    : result(soakPass ? "PASS" : "FAIL", [relativeArtifact(evidenceDir, soakFile), relativeArtifact(evidenceDir, soakEvidenceFile)], {
      details: {
        verdict: soak.verdict,
        cycles: soak.cycles,
        observedSeconds: soak.observed_seconds,
        evidenceCycles: soakRecords?.length ?? 0,
        anchorSequenceGapTotal: soak.anchor_sequence_gap_total,
        findings: soak.findings,
      },
      ...(soakPass ? {} : { remediation: ["Run the hourly synthetic soak until soak.jsonl has at least 73 finalized cycles covering 72 hours and the report is Passed with no findings."] }),
    });

  const requiredCheckRecords = REQUIRED_CHECKS.map((id) => checks.get(id));
  const failedRequiredCheck = requiredCheckRecords.some((check) => check !== undefined && check.status !== "PASS");
  const missingRequiredCheck = requiredCheckRecords.some((check) => check === undefined);
  const missingRequiredLog = requiredCheckRecords.some((check, index) => {
    if (check === undefined) return false;
    return !existsSync(checkLog(evidenceDir, checks, REQUIRED_CHECKS[index]));
  });
  const implementationChecksResult = result(
    failedRequiredCheck ? "FAIL" : (missingRequiredCheck || missingRequiredLog ? "NOT_RUN" : "PASS"),
    REQUIRED_CHECKS.map((id) => relativeArtifact(evidenceDir, checkLog(evidenceDir, checks, id))),
    failedRequiredCheck || missingRequiredCheck || missingRequiredLog
      ? { remediation: ["Run every required Gate C check and retain its command log before rendering the release report."] }
      : { details: { requiredChecks: REQUIRED_CHECKS } },
  );

  const incidentLogFile = checkLog(evidenceDir, checks, "incident-index");
  const verifierLogFile = checkLog(evidenceDir, checks, "verifier-tests");
  const incidentLog = await readText(incidentLogFile);
  const verifierLog = await readText(verifierLogFile);
  const incidentEvidence = {
    finalizedOpenAndResolve: /an opened incident becomes an OPEN notice/.test(incidentLog ?? "")
      && /a resolve event clears the current status/.test(incidentLog ?? ""),
    watermarkSafety: /an interrupted scan keeps the old watermark/.test(incidentLog ?? ""),
    staleIndexIsNotVerified: /stale watermark cannot produce VERIFIED/.test(verifierLog ?? ""),
  };
  const incidentChecksPass = checkStatus(checks, "incident-index") === "PASS"
    && checkStatus(checks, "verifier-tests") === "PASS";
  const incidentEvidencePass = Object.values(incidentEvidence).every(Boolean);
  const incidentStatus = !checks.has("incident-index") && !checks.has("verifier-tests")
    ? "NOT_RUN"
    : !incidentChecksPass || !incidentEvidencePass ? "FAIL" : "PASS";
  const incidentResult = result(
    incidentStatus,
    [
      relativeArtifact(evidenceDir, incidentLogFile),
      relativeArtifact(evidenceDir, verifierLogFile),
    ],
    incidentStatus === "PASS"
      ? { details: incidentEvidence }
      : { remediation: REMEDIATIONS["incident-index"] },
  );

  const browserLogFile = checkLog(evidenceDir, checks, "browser-e2e");
  const browserReportDir = resolve(evidenceDir, "browser-playwright-report");
  const browserOutputDir = resolve(evidenceDir, "browser-test-results");
  const browserArtifactsPass = checkStatus(checks, "browser-e2e") === "PASS"
    && existsSync(browserLogFile)
    && existsSync(browserReportDir)
    && await hasFileWithExtension(browserOutputDir, ".zip")
    && await hasFileWithExtension(browserOutputDir, ".png");
  const browserStatus = !checks.has("browser-e2e")
    ? "NOT_RUN"
    : checkStatus(checks, "browser-e2e") !== "PASS" || !browserArtifactsPass ? "FAIL" : "PASS";
  const browserResult = result(
    browserStatus,
    [
      relativeArtifact(evidenceDir, browserLogFile),
      relativeArtifact(evidenceDir, browserReportDir),
      relativeArtifact(evidenceDir, browserOutputDir),
    ],
    browserStatus === "PASS" ? {} : { remediation: REMEDIATIONS["browser-e2e"] },
  );

  const backupLogFile = checkLog(evidenceDir, checks, "backup-recovery-e2e");
  const backupReportDir = resolve(evidenceDir, "backup-playwright-report");
  const backupOutputDir = resolve(evidenceDir, "backup-test-results");
  const backupLog = await readText(backupLogFile);
  const backupAssertions = {
    allActiveCenters: /bootstraps five centers, adds a sixth, and replicates one immutable snapshot/.test(backupLog ?? ""),
    retry: /shows partial success and retries the same pending replica/.test(backupLog ?? ""),
    retentionTwelve: /retention keeps twelve folders and preserves the finalized snapshot/.test(backupLog ?? ""),
    insufficientTwoOfFive: /recovery rejects two shares before creating an approval operation/.test(backupLog ?? ""),
    corruptPackageAndRootMismatch: /ciphertext and root failures stop recovery before Restore Approval/.test(backupLog ?? ""),
    chiefApprovalThreeOfFive: /three shares wait for chief approval, preserve the binding, and restore the full state/.test(backupLog ?? ""),
  };
  const backupAssertionsPass = Object.values(backupAssertions).every(Boolean);
  const backupArtifactsPass = checkStatus(checks, "backup-recovery-e2e") === "PASS"
    && existsSync(backupLogFile)
    && existsSync(backupReportDir)
    && await hasFileWithExtension(backupOutputDir, ".zip")
    && await hasFileWithExtension(backupOutputDir, ".png");
  const backupStatus = !checks.has("backup-recovery-e2e")
    ? "NOT_RUN"
    : checkStatus(checks, "backup-recovery-e2e") !== "PASS" || !backupArtifactsPass || !backupAssertionsPass ? "FAIL" : "PASS";
  const backupResult = result(
    backupStatus,
    [
      relativeArtifact(evidenceDir, backupLogFile),
      relativeArtifact(evidenceDir, backupReportDir),
      relativeArtifact(evidenceDir, backupOutputDir),
    ],
    backupStatus === "PASS"
      ? { details: { ...backupAssertions, activeBackupCenters: 6, baselineActiveBackupCenters: 5, retentionWindow: 12, threshold: "3-of-5" } }
      : { remediation: REMEDIATIONS["backup-recovery-e2e"] },
  );

  let liveResult = await liveSmokeEvidence(evidenceDir);
  if (checkStatus(checks, "live-smoke") === "FAIL") {
    liveResult = result("FAIL", liveResult.evidence, { remediation: REMEDIATIONS["live-smoke"] });
  } else if (checkStatus(checks, "live-smoke") === "PASS" && liveResult.status !== "PASS") {
    liveResult = result("FAIL", liveResult.evidence, {
      reason: "The live-smoke command passed without a valid live evidence artifact.",
      remediation: REMEDIATIONS["live-smoke"],
    });
  }
  const preflight = checks.get("preflight");
  const preflightResult = preflight === undefined
    ? result("NOT_RUN", ["checks/preflight.log"], { remediation: REMEDIATIONS.preflight })
    : result(preflight.status === "PASS" && existsSync(checkLog(evidenceDir, checks, "preflight")) ? "PASS" : "FAIL", [relativeArtifact(evidenceDir, checkLog(evidenceDir, checks, "preflight"))], {
      ...(preflight.status === "PASS" ? {} : { remediation: preflight.remediation ?? REMEDIATIONS.preflight }),
    });

  const reportHasInput = checks.size > 0 || soak !== null || liveResult.status !== "NOT_RUN";
  const reportResult = result(
    reportHasInput ? "PASS" : "NOT_RUN",
    [relativeArtifact(evidenceDir, resolve(evidenceDir, "checks"))],
    reportHasInput ? { details: { indexedAcceptanceResults: true } } : { remediation: ["Collect at least one Gate C evidence source before rendering a release report."] },
  );

  const acceptance = [
    { id: "GATE-C-CHECKS", title: "All required implementation, typecheck, drift and browser checks passed", ...implementationChecksResult },
    { id: "GATE-C-PREFLIGHT", title: "Clean-host preflight passed or recorded remediation before mutation", ...preflightResult },
    { id: "GATE-C-SOAK", title: "72-hour synthetic soak without manual intervention", ...soakResult },
    { id: "GATE-C-MANIFEST", title: "Sequence continuity and reproducible manifestHash", ...soakResult },
    { id: "GATE-C-INCIDENT", title: "Finalized incident index and fail-closed stale/unavailable behavior", ...incidentResult },
    { id: "GATE-C-BROWSER", title: "Import, preview, reviewed signing, QR, VERIFIED, INVALID and DISPUTED browser flow", ...browserResult },
    { id: "GATE-C-LIVE", title: "Separately approved live-devnet QR to finalized anchor to VERIFIED smoke", ...liveResult },
    { id: "GATE-C-BACKUP", title: "Bounded Backup Center, Snapshot, retry, retention and recovery acceptance", ...backupResult },
    { id: "GATE-C-SCOPE", title: "Evidence is explicitly bounded synthetic MVP evidence", status: "PASS", evidence: [] },
    { id: "GATE-C-REPORT", title: "Acceptance results, traces/screenshots and remediation are indexed", ...reportResult },
  ];

  const failed = acceptance.filter((item) => item.status === "FAIL");
  const incomplete = acceptance.filter((item) => item.status === "NOT_RUN");
  const verdict = failed.length > 0 ? "FAIL" : incomplete.length > 0 ? "INCOMPLETE" : "PASS";
  const report = {
    schema: "onelayer.gate-c.release-report.v1",
    generated_at: new Date().toISOString(),
    verdict,
    classification: "BOUNDED_SYNTHETIC_MVP",
    acceptance,
    checks: [...checks.values()],
    scope: {
      claims: [
        "Synthetic pilot evidence is reproducible from the recorded JSONL and command artifacts.",
        "Deterministic browser and bounded local backup/recovery acceptance are represented by their traces and logs.",
        "Live-devnet evidence is accepted only from the separately approved smoke artifact.",
      ],
      exclusions: EXCLUSIONS,
    },
    remediation: [...new Set(acceptance.flatMap((item) => item.remediation ?? []))],
  };

  await writeAtomic(resolve(evidenceDir, "release-report.json"), `${JSON.stringify(report, null, 2)}\n`);
  const lines = [
    "# OneLayer Gate C release report",
    "",
    `- Verdict: **${verdict}**`,
    "- Classification: **BOUNDED_SYNTHETIC_MVP**",
    "",
    "## Acceptance",
    "",
    "| Criterion | Result | Evidence |",
    "|---|---|---|",
    ...acceptance.map((item) => `| ${item.title} | ${item.status} | ${item.evidence.length === 0 ? "scope/report metadata" : item.evidence.map((file) => `\`${file}\``).join(", ")} |`),
    "",
    "## Explicit exclusions",
    "",
    ...EXCLUSIONS.map((item) => `- ${item}`),
    "",
    "## Remediation",
    "",
    ...(report.remediation.length === 0 ? ["- None recorded."] : report.remediation.map((item) => `- ${item}`)),
    "",
    "The JSON report is the machine-readable release artifact; logs and Playwright output are retained at the paths listed above.",
    "",
  ];
  await writeAtomic(resolve(evidenceDir, "release-report.md"), `${lines.join("\n")}\n`);
  process.stdout.write(`${JSON.stringify({ verdict, report: resolve(evidenceDir, "release-report.json") })}\n`);
  return verdict;
}

async function record(args) {
  const [directory, id, exitCodeText, log, ...commandParts] = args;
  if (!directory || !id || exitCodeText === undefined || !log) {
    throw new Error("usage: release-report.mjs record <dir> <id> <exitCode> <log> [command...]");
  }
  const evidenceDir = evidenceDirFromArg(directory);
  const exitCode = Number(exitCodeText);
  if (!Number.isSafeInteger(exitCode) || exitCode < 0) throw new Error("exitCode is invalid");
  const check = {
    id,
    status: exitCode === 0 ? "PASS" : "FAIL",
    exit_code: exitCode,
    command: commandParts.join(" "),
    log: relativeArtifact(evidenceDir, resolve(log)),
    ...(exitCode === 0 ? {} : { remediation: REMEDIATIONS[id] ?? ["Inspect the recorded log and rerun the failed check after remediation."] }),
  };
  await writeAtomic(resolve(evidenceDir, `checks/${id}.json`), `${JSON.stringify(check, null, 2)}\n`);
}

const command = process.argv[2] ?? "render";
try {
  if (command === "record") {
    await record(process.argv.slice(3));
  } else if (command === "render") {
    const verdict = await render(evidenceDirFromArg(process.argv[3]));
    if (verdict === "FAIL") process.exitCode = 2;
    if (verdict === "INCOMPLETE") process.exitCode = 3;
  } else {
    throw new Error("usage: release-report.mjs [record <dir> <id> <exitCode> <log> [command...]|render [dir]]");
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
