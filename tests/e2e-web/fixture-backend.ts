// Deterministic stand-in for demo-api and the verifier used by the browser E2E.
//
// It reproduces the Admin API contract — sessions, roles, CSRF, idempotency,
// the transaction state machine and QR hash binding — with scripted chain
// responses, so the browser flow runs without a validator or SOL. The
// cryptographic behaviour it stands in for is covered by the unit tests in
// apps/demo-api, apps/verifier and packages/*.
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

export const OPERATOR_PASSWORD = "operator-password-0123456789";
export const AUDITOR_PASSWORD = "auditor-password-0123456789";
export const CHIEF_ADMIN_PASSWORD = "chief-admin-password-0123456789";
export const WALLET_ADDRESS = "9zjRUZLLE4nRvXtDkYPJDGnnLrLrGCUbHVLbdaFmMbJq";

export interface Scenario {
  /** Verifier answer for the freshly issued certificate. */
  verification?: Record<string, unknown>;
  /** Simulates the on-chain RegistryConfig.pause flag. */
  registryPaused?: boolean;
  simulationFails?: boolean;
  blockhashExpired?: boolean;
  unavailableCenterIds?: string[];
  snapshotFinalized?: boolean;
  corruptCiphertext?: boolean;
  plaintextHashMismatch?: boolean;
  rootMismatch?: boolean;
  decryptionFails?: boolean;
  anchorUnavailable?: boolean;
  openIncident?: boolean;
}

interface Session {
  username: string;
  role: "operator" | "auditor" | "chief_admin";
  csrfToken: string;
}

interface Intent {
  intentId: string;
  state: string;
  batchSequence: string;
  intentHash: string;
  review: Record<string, unknown>;
  recentBlockhash: string;
  lastValidBlockHeight: string;
  expiresAt: string;
  transactionSignature: string | null;
  anchorSlot: string | null;
  certificateId: string | null;
  failureCode: string | null;
  simulationLogs: string[];
}

interface FixtureCenter {
  centerId: string;
  name: string;
  volumeName: string;
  credentialReference: string;
  credentialVersion: string;
  folders: FixtureFolder[];
}

interface FixtureFolder {
  snapshotId: string;
  snapshotVersion: string;
  objectKey: string;
  status: "COPIED" | "PENDING_RETRY" | "FAILED";
  snapshotStatus: "FINALIZED" | "NON_FINALIZED";
  plaintextHash: string;
  ciphertextHash: string;
  merkleRoot: string;
  lastError: string | null;
  createdAt: string;
  verifiedAt: string | null;
}

interface FixtureSnapshot {
  snapshotId: string;
  snapshotVersion: string;
  snapshotStatus: "FINALIZED" | "NON_FINALIZED";
  plaintextHash: string;
  ciphertextHash: string;
  merkleRoot: string;
  createdAt: string;
  operationId: string;
}

interface FixtureRecoveryOperation {
  operationId: string;
  centerId: string;
  snapshotId: string;
  snapshotVersion: string;
  snapshotStatus: "FINALIZED" | "NON_FINALIZED";
  target: string;
  merkleRoot: string;
  plaintextHash: string;
  ciphertextHash: string;
  anchor: {
    batchSequence: string;
    anchorSlot: string;
    transactionSignature: string;
    merkleRoot: string;
    finalizedAt: string;
  };
  state: "AWAITING_APPROVAL" | "APPROVED" | "RESTORED" | "FAILED";
  failureCode: string | null;
  approvedBy: string | null;
  approval: Record<string, unknown> | null;
  restoredTarget: Record<string, unknown> | null;
}

const MERKLE_ROOT = "aa".repeat(32);
const MANIFEST_HASH = "bb".repeat(32);
const PREVIOUS_ANCHOR = "cc".repeat(32);
const PROGRAM_ID = "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo";
const SEGMENT_PDA = "5vJRnEr1x8ChoVvVaSBLQ3PXfBEcbLmqLgN4uWvyfHKJ";
const SIGNATURE = "5".repeat(88);
const CERTIFICATE_PACKAGE = "Q0VSVElGSUNBVEUtUEFDS0FHRS1GSVhUVVJF";
const SCHEMA_ID = "land-registry-v1";

// These are test-only out-of-band custody artifacts. The fixture accepts them
// to stand in for three valid shares; it never returns or records their text.
export const RECOVERY_SHARES = [
  `ONELAYER_RECOVERY_SHARE_V1:1:${"11".repeat(32)}`,
  `ONELAYER_RECOVERY_SHARE_V1:2:${"22".repeat(32)}`,
  `ONELAYER_RECOVERY_SHARE_V1:3:${"33".repeat(32)}`,
  `ONELAYER_RECOVERY_SHARE_V1:4:${"44".repeat(32)}`,
  `ONELAYER_RECOVERY_SHARE_V1:5:${"55".repeat(32)}`,
] as const;

/**
 * Same shape as `describeSchema()` in apps/demo-api, trimmed to the paths the
 * browser scenarios use. The schema itself is unit-tested there.
 */
const SCHEMA_FIELDS = [
  {
    path: "status",
    type: "text",
    required: true,
    label: "Record status",
    values: ["ACTIVE", "ARCHIVED", "PENDING", "DISPUTED"],
    maxBytes: null,
    scale: null,
    example: "ACTIVE",
    hint: "Lifecycle of the registry record itself.",
  },
  {
    path: "cadastralNumber",
    type: "text",
    required: true,
    label: "Cadastral number",
    values: null,
    maxBytes: 64,
    scale: null,
    example: "01-004-0123-045",
    hint: "Identifier of the parcel in the registry.",
  },
  {
    path: "areaSquareMeters",
    type: "decimal",
    required: false,
    label: "Area (m²)",
    values: null,
    maxBytes: null,
    scale: 2,
    example: "1250.50",
    hint: "Decimal string with exactly two digits after the point.",
  },
] as const;

function certificateHashOf(certificateId: string): string {
  return createHash("sha256").update(`fixture:${certificateId}`).digest("hex");
}

function qrHash(certificateId: string): string {
  return Buffer.from(certificateHashOf(certificateId), "hex").toString("base64url");
}

export function createFixtureBackend(
  webBaseUrl: string,
  initial: Scenario = {},
): { server: Server; port: () => number } {
  let scenario: Scenario = initial;
  const sessions = new Map<string, Session>();
  const intents = new Map<string, Intent>();
  const idempotency = new Map<string, string>();
  const records: Array<{
    internalRecordId: string;
    recordVersion: string;
    status: string;
    origin: string;
    sourceCursor: string;
    schemaId: string;
    fields: Array<{ path: string; type: string; value: string }>;
  }> = [
    {
      internalRecordId: "SYNTHETIC-1",
      recordVersion: "1",
      status: "ACTIVE",
      origin: "FIXTURE",
      sourceCursor: "1",
      schemaId: SCHEMA_ID,
      fields: [{ path: "cadastralNumber", type: "text", value: "01-004-0123-045" }],
    },
    {
      internalRecordId: "SYNTHETIC-2",
      recordVersion: "1",
      status: "ACTIVE",
      origin: "FIXTURE",
      sourceCursor: "2",
      schemaId: SCHEMA_ID,
      fields: [{ path: "cadastralNumber", type: "text", value: "01-004-0123-046" }],
    },
  ];
  const certificates: Array<{
    certificateId: string;
    batchSequence: string;
    status: string;
    issuedAt: string;
    qrUrl: string;
    internalRecordId: string;
    recordVersion: string;
    certificateHash: string;
    disclosureMode: string;
    disclosedPaths: string[];
  }> = [];
  const timeline: Array<Record<string, unknown>> = [];
  const centers: FixtureCenter[] = Array.from({ length: 5 }, (_unused, index) => {
    const ordinal = String(index + 1).padStart(2, "0");
    return {
      centerId: `BACKUPCENTER-${index + 1}`,
      name: `Local BackupCenter ${ordinal}`,
      volumeName: `onelayer-backup-volume-${ordinal}`,
      credentialReference: `onelayer-backup-credential-${ordinal}`,
      credentialVersion: "credential-v1",
      folders: [],
    };
  });
  const snapshots: FixtureSnapshot[] = [];
  const backupIdempotency = new Map<string, string>();
  const recoveryOperations: FixtureRecoveryOperation[] = [];
  let sequence = 0;

  function fixtureNow(): string {
    return new Date(1_800_000_000_000 + sequence * 1000).toISOString();
  }

  function centerAvailable(centerId: string): boolean {
    return !(scenario.unavailableCenterIds ?? []).includes(centerId);
  }

  function registryIsWorking(): boolean {
    return scenario.registryPaused !== true;
  }

  function folderIsFinalized(folder: FixtureFolder): boolean {
    return folder.snapshotStatus === "FINALIZED";
  }

  function applyRetention(center: FixtureCenter): void {
    while (center.folders.length > 12) {
      const sorted = [...center.folders].sort((left, right) =>
        left.createdAt.localeCompare(right.createdAt) || left.snapshotId.localeCompare(right.snapshotId),
      );
      const finalized = sorted.filter(folderIsFinalized);
      const victim = sorted.find((folder) => !folderIsFinalized(folder)) ??
        (finalized.length > 1 ? finalized[0] : undefined);
      if (victim === undefined) throw new Error("retention would remove the only finalized snapshot");
      center.folders.splice(center.folders.indexOf(victim), 1);
    }
  }

  function backupCenterBody(center: FixtureCenter): Record<string, unknown> {
    const unavailable = !centerAvailable(center.centerId);
    const folders = [...center.folders].sort((left, right) => right.createdAt.localeCompare(left.createdAt));
    return {
      centerId: center.centerId,
      id: center.centerId,
      name: center.name,
      scope: "LOCAL",
      type: "LOCAL",
      endpoint: `local://backup-center-${center.centerId.replace("BACKUPCENTER-", "")}`,
      localEndpoint: `local://backup-center-${center.centerId.replace("BACKUPCENTER-", "")}`,
      volume: { name: center.volumeName, reference: center.volumeName },
      volumeName: center.volumeName,
      credentials: { reference: center.credentialReference, version: center.credentialVersion },
      credentialReference: center.credentialReference,
      credentialVersion: center.credentialVersion,
      active: true,
      health: { status: unavailable ? "UNAVAILABLE" : "HEALTHY", available: !unavailable, checkedAt: fixtureNow() },
      healthStatus: unavailable ? "UNAVAILABLE" : "HEALTHY",
      replicaStatus: {
        copied: folders.filter((folder) => folder.status === "COPIED").length,
        pendingRetry: folders.filter((folder) => folder.status === "PENDING_RETRY").length,
        failed: folders.filter((folder) => folder.status === "FAILED").length,
        total: folders.length,
      },
      lastReplicaStatus: folders[0]?.status ?? "EMPTY",
      retiredFolderCount: Math.max(0, snapshots.length - folders.length),
      retentionWindow: 12,
      folders,
    };
  }

  function backupOverview(): Record<string, unknown> {
    return {
      registryId: "gov.registry.land",
      packageFormat: "SnapshotPackageV1",
      retentionWindow: 12,
      centers: centers.map(backupCenterBody),
      backupCenters: centers.map(backupCenterBody),
      snapshots: snapshots
        .slice()
        .sort((left, right) => Number(right.snapshotVersion) - Number(left.snapshotVersion))
        .map((snapshot) => ({
          ...snapshot,
          formatVersion: 1,
          packageFormat: "SnapshotPackageV1",
          plaintextLength: 128,
          keyEncryptionVersion: "mvp-memory-kek-v1",
          createdBy: "operator",
          replicas: centers.flatMap((center) => center.folders
            .filter((folder) => folder.snapshotId === snapshot.snapshotId)
            .map((folder) => ({
              centerId: center.centerId,
              objectKey: folder.objectKey,
              status: folder.status,
              copyStatus: folder.status,
              lastError: folder.lastError,
              createdAt: folder.createdAt,
              verifiedAt: folder.verifiedAt,
            }))),
        })),
    };
  }

  function backupOperationBody(snapshot: FixtureSnapshot, replayed = false): Record<string, unknown> {
    const overview = backupOverview();
    const snapshotSummary = (overview.snapshots as Array<Record<string, any>>)
      .find((candidate) => candidate.snapshotId === snapshot.snapshotId);
    return {
      operationId: snapshot.operationId,
      snapshotId: snapshot.snapshotId,
      snapshotVersion: snapshot.snapshotVersion,
      formatVersion: 1,
      packageFormat: "SnapshotPackageV1",
      snapshotStatus: snapshot.snapshotStatus,
      merkleRoot: snapshot.merkleRoot,
      plaintextHash: snapshot.plaintextHash,
      ciphertextHash: snapshot.ciphertextHash,
      plaintextLength: 128,
      keyEncryptionVersion: "mvp-memory-kek-v1",
      createdAt: snapshot.createdAt,
      operationStatus: (snapshotSummary?.replicas ?? []).every((replica: any) => replica.copyStatus === "COPIED")
        ? "COMPLETED" : "PARTIAL",
      replayed,
      replicas: snapshotSummary?.replicas ?? [],
      centers: centers.map((center) => ({
        centerId: center.centerId,
        name: center.name,
        health: backupCenterBody(center).health,
        status: center.folders.find((folder) => folder.snapshotId === snapshot.snapshotId)?.status ?? "PENDING_RETRY",
        folder: center.folders.find((folder) => folder.snapshotId === snapshot.snapshotId) ?? null,
      })),
    };
  }

  function recoveryOperationBody(operation: FixtureRecoveryOperation, replayed = false): Record<string, unknown> {
    return {
      recoveryOperationId: operation.operationId,
      operationId: operation.operationId,
      registryId: "gov.registry.land",
      centerId: operation.centerId,
      snapshotId: operation.snapshotId,
      snapshotVersion: operation.snapshotVersion,
      snapshotStatus: operation.snapshotStatus,
      target: operation.target,
      state: operation.state,
      status: operation.state,
      anchor: operation.anchor,
      selectedAnchor: operation.anchor,
      merkleRoot: operation.merkleRoot,
      plaintextHash: operation.plaintextHash,
      ciphertextHash: operation.ciphertextHash,
      shareThreshold: 3,
      validation: operation.state === "FAILED" ? null : {
        threshold: "3-of-5",
        ciphertextHash: "MATCH",
        plaintextHash: "MATCH",
        merkleRoot: "MATCH",
      },
      failureCode: operation.failureCode,
      approvedBy: operation.approvedBy,
      approval: operation.approval,
      restoredTarget: operation.restoredTarget,
      replayed,
    };
  }

  function record(eventType: string, session: Session | null, payload: Record<string, unknown>): void {
    sequence += 1;
    timeline.unshift({
      sequence: String(sequence),
      intentId: null,
      eventType,
      actor: session?.username ?? "system",
      actorRole: session?.role ?? "system",
      payload,
      createdAt: new Date(1_800_000_000_000 + sequence * 1000).toISOString(),
    });
  }

  /** Minimal stand-in for the schema validation unit-tested in apps/demo-api. */
  function validate(
    internalRecordId: unknown,
    fields: Record<string, unknown>,
  ): { status: string; fields: Array<{ path: string; type: string; value: string }> } | { code: string; path: string } {
    if (typeof internalRecordId !== "string" || !/^SYNTHETIC-[1-9][0-9]*$/.test(internalRecordId)) {
      return { code: "INTERNAL_RECORD_ID_INVALID", path: "internalRecordId" };
    }
    const validated: Array<{ path: string; type: string; value: string }> = [];
    for (const [path, raw] of Object.entries(fields)) {
      const definition = SCHEMA_FIELDS.find((candidate) => candidate.path === path);
      if (definition === undefined) return { code: "CANONICALIZATION_FAILED", path };
      const value = String(raw).trim();
      if (value.length === 0) continue;
      if (definition.values !== null && !(definition.values as readonly string[]).includes(value)) {
        return { code: "FIELD_VALUE_NOT_ALLOWED", path };
      }
      if (definition.type === "decimal" && !/^-?(?:0|[1-9][0-9]*)\.[0-9]{2}$/.test(value)) {
        return { code: "FIELD_DECIMAL_INVALID", path };
      }
      validated.push({ path, type: definition.type, value });
    }
    for (const definition of SCHEMA_FIELDS) {
      if (definition.required && !validated.some((field) => field.path === definition.path)) {
        return { code: "FIELD_REQUIRED_MISSING", path: definition.path };
      }
    }
    return {
      status: validated.find((field) => field.path === "status")!.value,
      fields: validated.filter((field) => field.path !== "status"),
    };
  }

  function upsert(body: Record<string, unknown> | null): {
    internalRecordId: string;
    recordVersion: string;
    status: string;
    origin: string;
  } | null {
    const fields = { ...(body?.fields as Record<string, unknown> ?? {}) };
    if (typeof body?.status === "string" && fields.status === undefined) fields.status = body.status;
    const validated = validate(body?.internalRecordId, fields);
    if ("code" in validated) return null;
    const internalRecordId = String(body?.internalRecordId);
    const existing = records.find((row) => row.internalRecordId === internalRecordId);
    if (existing === undefined) {
      records.push({
        internalRecordId,
        recordVersion: "1",
        status: validated.status,
        origin: "ADMIN_UI",
        sourceCursor: String(records.length + 1),
        schemaId: SCHEMA_ID,
        fields: validated.fields,
      });
      return { internalRecordId, recordVersion: "1", status: validated.status, origin: "ADMIN_UI" };
    }
    existing.recordVersion = String(Number(existing.recordVersion) + 1);
    existing.status = validated.status;
    existing.fields = validated.fields;
    return {
      internalRecordId,
      recordVersion: existing.recordVersion,
      status: existing.status,
      origin: existing.origin,
    };
  }

  interface AcceptedRow {
    row: number;
    internalRecordId: string;
    status: string;
    fields: Array<{ path: string; type: string; value: string }>;
  }

  function fieldMap(entry: AcceptedRow): Record<string, string> {
    return Object.fromEntries([
      ["status", entry.status],
      ...entry.fields.map((field) => [field.path, field.value] as const),
    ]);
  }

  function parseImport(body: Record<string, unknown> | null): {
    accepted: AcceptedRow[];
    rejected: Array<{ row: number; code: string; path: string | null }>;
    applied: Array<Record<string, unknown>>;
  } {
    const accepted: AcceptedRow[] = [];
    const rejected: Array<{ row: number; code: string; path: string | null }> = [];
    const rows: Array<{ row: number; internalRecordId: unknown; fields: Record<string, unknown> }> = [];
    if (body?.format === "csv") {
      const lines = String(body.content ?? "").split(/\r?\n/).filter((line) => line.trim().length > 0);
      const header = (lines[0] ?? "").split(",").map((column) => column.trim());
      lines.slice(1).forEach((line, index) => {
        const values = line.split(",").map((value) => value.trim());
        const fields: Record<string, unknown> = {};
        let internalRecordId: unknown;
        header.forEach((column, position) => {
          if (column === "internalRecordId") { internalRecordId = values[position]; return; }
          if ((values[position] ?? "").length > 0) fields[column] = values[position];
        });
        rows.push({ row: index + 2, internalRecordId, fields });
      });
    } else {
      const parsed: unknown = typeof body?.content === "string" ? JSON.parse(body.content) : body?.records;
      const items = Array.isArray(parsed) ? parsed : [parsed];
      items.forEach((item: any, index) => {
        rows.push({ row: index + 1, internalRecordId: item?.internalRecordId, fields: item?.fields ?? {} });
      });
    }
    for (const entry of rows) {
      const validated = validate(entry.internalRecordId, entry.fields);
      if ("code" in validated) {
        rejected.push({ row: entry.row, code: validated.code, path: validated.path });
        continue;
      }
      accepted.push({
        row: entry.row,
        internalRecordId: String(entry.internalRecordId),
        status: validated.status,
        fields: validated.fields,
      });
    }
    return { accepted, rejected, applied: [] };
  }

  /** Canonical preview shape shared by `/preview` and the intent review. */
  function previewRecord(
    row: { internalRecordId: string; recordVersion: string; status: string; fields: Array<{ path: string; value: string }> },
    index: number,
  ): Record<string, unknown> {
    const fields = [{ path: "status", value: row.status }, ...row.fields];
    return {
      internalRecordId: row.internalRecordId,
      recordVersion: row.recordVersion,
      recordIdCommitment: `${index + 1}`.repeat(64).slice(0, 64),
      fieldRoot: "dd".repeat(32),
      recordCommitment: "ee".repeat(32),
      batchLeafHash: "ff".repeat(32),
      leafIndex: index,
      disclosedFields: Object.fromEntries(fields.map((field) => [field.path, field.value])),
      fields: fields.map((field, position) => ({
        path: field.path,
        value: field.value,
        fieldCommitment: `${position + 1}`.repeat(64).slice(0, 64),
        fieldLeafIndex: position,
      })),
    };
  }

  function json(response: ServerResponse, status: number, body: unknown, cookie?: string): void {
    const encoded = body === null ? "" : JSON.stringify(body);
    const headers: Record<string, string> = {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    };
    if (cookie !== undefined) headers["set-cookie"] = cookie;
    response.writeHead(status, headers);
    response.end(encoded);
  }

  async function readBody(request: IncomingMessage): Promise<any> {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    if (chunks.length === 0) return null;
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  }

  function sessionOf(request: IncomingMessage): Session | null {
    const cookie = /onelayer_admin_session=([^;]+)/.exec(request.headers.cookie ?? "");
    return cookie === null ? null : sessions.get(cookie[1]) ?? null;
  }

  function csrfOk(request: IncomingMessage, session: Session): boolean {
    const supplied = request.headers["x-onelayer-csrf"];
    if (typeof supplied !== "string") return false;
    const left = Buffer.from(supplied);
    const right = Buffer.from(session.csrfToken);
    return left.length === right.length && timingSafeEqual(left, right);
  }

  const server = createServer((request, response) => {
    void handle(request, response).catch(() => json(response, 500, { code: "FIXTURE_ERROR" }));
  });

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? "/", "http://fixture.local");
    const method = request.method ?? "GET";

    // Test-only control plane: selects the scripted chain answers.
    if (url.pathname === "/__fixture/scenario" && method === "POST") {
      const nextScenario = (await readBody(request)) ?? {};
      if (nextScenario.resetBackups === true) {
        snapshots.splice(0, snapshots.length);
        recoveryOperations.splice(0, recoveryOperations.length);
        backupIdempotency.clear();
        centers.forEach((center) => { center.folders.splice(0, center.folders.length); });
        centers.splice(5);
      }
      scenario = nextScenario;
      json(response, 200, { scenario });
      return;
    }

    if (url.pathname === "/v1/admin/session" && method === "POST") {
      const body = await readBody(request);
      const expected = body?.username === "operator"
        ? OPERATOR_PASSWORD
        : body?.username === "chief_admin" ? CHIEF_ADMIN_PASSWORD : AUDITOR_PASSWORD;
      if ((body?.username !== "operator" && body?.username !== "auditor" && body?.username !== "chief_admin") || body?.password !== expected) {
        json(response, 401, { code: "INVALID_CREDENTIALS" });
        return;
      }
      const sessionId = randomUUID();
      const session: Session = { username: body.username, role: body.username, csrfToken: randomUUID() };
      sessions.set(sessionId, session);
      json(
        response,
        201,
        { role: session.role, username: session.username, csrfToken: session.csrfToken },
        `onelayer_admin_session=${sessionId}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800`,
      );
      return;
    }

    if (url.pathname.startsWith("/v1/admin/")) {
      const session = sessionOf(request);
      if (session === null) { json(response, 401, { code: "SESSION_REQUIRED" }); return; }
      if (method !== "GET" && !csrfOk(request, session)) {
        json(response, 403, { code: "CSRF_TOKEN_INVALID" });
        return;
      }
      await handleAdmin(request, response, url, method, session);
      return;
    }

    const packagePath = /^\/v1\/certificates\/([0-9a-f]{32})\/package$/.exec(url.pathname);
    if (packagePath !== null && method === "GET") {
      if (!registryIsWorking()) { json(response, 409, { code: "REGISTRY_PAUSED" }); return; }
      const certificateId = packagePath[1];
      if (!certificates.some((certificate) => certificate.certificateId === certificateId)) {
        json(response, 404, { code: "CERTIFICATE_NOT_FOUND" });
        return;
      }
      const supplied = url.searchParams.get("h");
      if (supplied !== null && supplied !== qrHash(certificateId)) {
        json(response, 422, { code: "QR_HASH_MISMATCH" });
        return;
      }
      json(response, 200, {
        package_base64url: CERTIFICATE_PACKAGE,
        certificateHash: certificateHashOf(certificateId),
      });
      return;
    }

    const metadataPath = /^\/v1\/certificates\/([0-9a-f]{32})\/metadata$/.exec(url.pathname);
    if (metadataPath !== null && method === "GET") {
      if (!registryIsWorking()) { json(response, 409, { code: "REGISTRY_PAUSED" }); return; }
      const certificate = certificates.find((candidate) => candidate.certificateId === metadataPath[1]);
      if (certificate === undefined) { json(response, 404, { code: "CERTIFICATE_NOT_FOUND" }); return; }
      json(response, 200, {
        certificateId: certificate.certificateId,
        registryId: "gov.registry.land",
        cluster: "solana:devnet",
        status: certificate.status,
        issuedAt: certificate.issuedAt,
        recordVersion: certificate.recordVersion,
        certificateHash: certificate.certificateHash,
        qrUrl: certificate.qrUrl,
        disclosureMode: certificate.disclosureMode,
        disclosedPaths: certificate.disclosedPaths,
        batchSequence: certificate.batchSequence,
        anchorSlot: "412346000",
        transactionSignature: SIGNATURE,
        merkleRoot: MERKLE_ROOT,
        manifestHash: MANIFEST_HASH,
        explorerUrl: `https://explorer.solana.com/tx/${SIGNATURE}?cluster=devnet`,
      });
      return;
    }

    if (/^\/v1\/qr\/[0-9a-f]{32}\.svg$/.test(url.pathname) && method === "GET") {
      if (!registryIsWorking()) { json(response, 409, { code: "REGISTRY_PAUSED" }); return; }
      const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"></svg>';
      response.writeHead(200, { "content-type": "image/svg+xml", "cache-control": "no-store" });
      response.end(svg);
      return;
    }

    if (/^\/v1\/qr\/[0-9a-f]{32}\.png$/.test(url.pathname) && method === "GET") {
      if (!registryIsWorking()) { json(response, 409, { code: "REGISTRY_PAUSED" }); return; }
      // One-pixel PNG: the browser scenarios only assert that the artifact is
      // served, the encoder itself is covered in apps/demo-api.
      const png = Buffer.from(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
        "base64",
      );
      response.writeHead(200, { "content-type": "image/png", "cache-control": "no-store", "content-length": png.length });
      response.end(png);
      return;
    }

    if (url.pathname === "/v1/verify" && method === "POST") {
      const body = await readBody(request);
      if (body?.certificatePackage !== CERTIFICATE_PACKAGE) {
        json(response, 422, {
          status: "INVALID",
          code: "CERT_SIGNATURE_INVALID",
          certificateId: "unknown",
          batchSequence: "1",
          warnings: [],
        });
        return;
      }
      if (!registryIsWorking()) {
        json(response, 422, {
          status: "INVALID",
          code: "REGISTRY_PAUSED",
          certificateId: certificates[0]?.certificateId ?? "unknown",
          batchSequence: "1",
          warnings: [],
        });
        return;
      }
      json(response, 200, scenario.verification ?? {
        status: "VERIFIED",
        certificateId: certificates[0]?.certificateId ?? "unknown",
        batchSequence: "1",
        solanaSlot: "412346000",
        incidentIndexStatus: "CHECKED",
        indexedThroughSlot: "412346040",
        rpcFinalizedHeadSlot: "412346050",
        indexLagSlots: "10",
        recordVersion: "1",
        currentRecordVersion: "1",
        certificateLifecycle: "ACTIVE",
        warnings: [],
      });
      return;
    }

    json(response, 404, { code: "NOT_FOUND" });
  }

  async function handleAdmin(
    request: IncomingMessage,
    response: ServerResponse,
    url: URL,
    method: string,
    session: Session,
  ): Promise<void> {
    if (url.pathname === "/v1/admin/session" && method === "GET") {
      json(response, 200, { role: session.role, username: session.username, csrfToken: session.csrfToken });
      return;
    }
    if (url.pathname === "/v1/admin/session" && method === "DELETE") {
      const cookie = /onelayer_admin_session=([^;]+)/.exec(request.headers.cookie ?? "");
      if (cookie !== null) sessions.delete(cookie[1]);
      json(response, 204, null);
      return;
    }
    if (url.pathname === "/v1/admin/schema" && method === "GET") {
      json(response, 200, { schemaId: SCHEMA_ID, fields: SCHEMA_FIELDS });
      return;
    }
    if (url.pathname === "/v1/admin/dashboard" && method === "GET") {
      json(response, 200, {
        registryId: "gov.registry.land",
        cluster: "solana:devnet",
        schemaId: SCHEMA_ID,
        records: {
          total: String(records.length),
          versions: String(records.reduce((total, row) => total + Number(row.recordVersion), 0)),
          imported: String(records.filter((row) => row.origin === "ADMIN_UI").length),
        },
        certificates: {
          byStatus: certificates.length === 0 ? {} : { ACTIVE: certificates.length },
          selective: certificates.filter((certificate) => certificate.disclosureMode === "SELECTIVE_FIELDS").length,
        },
        lastAnchor: certificates.length === 0 ? null : {
          batchSequence: "1",
          anchorSlot: "412346000",
          transactionSignature: SIGNATURE,
          merkleRoot: MERKLE_ROOT,
          finalizedAt: new Date(1_800_000_100_000).toISOString(),
          explorerUrl: `https://explorer.solana.com/tx/${SIGNATURE}?cluster=devnet`,
        },
        openIncidents: "0",
        intents: {},
      });
      return;
    }
    if ((url.pathname === "/v1/admin/recovery" || url.pathname === "/v1/admin/recovery/operations") && method === "GET") {
      json(response, 200, {
        operations: recoveryOperations
          .slice()
          .reverse()
          .map((operation) => recoveryOperationBody(operation)),
      });
      return;
    }
    if ((url.pathname === "/v1/admin/recovery/prepare" || url.pathname === "/v1/admin/recovery/operations") && method === "POST") {
      if (session.role !== "operator") { json(response, 403, { code: "ROLE_FORBIDDEN" }); return; }
      const body = await readBody(request);
      const shares = body?.recoveryShares ?? body?.shares;
      if (!Array.isArray(shares) || shares.length < 3) {
        json(response, 422, { code: "RECOVERY_SHARES_INSUFFICIENT" });
        return;
      }
      if (shares.length !== 3) {
        json(response, 422, { code: "RECOVERY_SHARE_COUNT" });
        return;
      }
      if (!shares.every((share: unknown) => typeof share === "string") ||
          new Set(shares).size !== shares.length ||
          !shares.every((share: string) => (RECOVERY_SHARES as readonly string[]).includes(share))) {
        json(response, 422, { code: "DECRYPTION_FAILED" });
        return;
      }
      const centerId = String(body?.centerId ?? body?.backupCenterId ?? "");
      const snapshotId = String(body?.snapshotId ?? "");
      const target = body?.target === undefined ? "local-demo-target" : String(body.target);
      const center = centers.find((candidate) => candidate.centerId === centerId);
      const snapshot = snapshots.find((candidate) => candidate.snapshotId === snapshotId);
      const folder = center?.folders.find((candidate) => candidate.snapshotId === snapshotId);
      if (center === undefined || snapshot === undefined || folder === undefined) {
        json(response, 404, { code: "RECOVERY_FOLDER_NOT_FOUND" });
        return;
      }
      if (folder.status !== "COPIED") {
        json(response, 409, { code: "RECOVERY_FOLDER_NOT_COPIED" });
        return;
      }
      if (!/^local-demo-[A-Za-z0-9._-]{1,80}$/.test(target)) {
        json(response, 400, { code: "TARGET_INVALID" });
        return;
      }
      if (snapshot.snapshotStatus !== "FINALIZED") {
        json(response, 409, { code: "SNAPSHOT_NOT_FINALIZED" });
        return;
      }
      if (scenario.anchorUnavailable === true) {
        json(response, 409, { code: "RECOVERY_ANCHOR_UNAVAILABLE" });
        return;
      }
      if (scenario.openIncident === true) {
        json(response, 409, { code: "RECOVERY_ANCHOR_UNAVAILABLE" });
        return;
      }
      if (scenario.corruptCiphertext === true) {
        json(response, 422, { code: "CIPHERTEXT_HASH_MISMATCH" });
        return;
      }
      if (scenario.plaintextHashMismatch === true) {
        json(response, 422, { code: "PLAINTEXT_HASH_MISMATCH" });
        return;
      }
      if (scenario.rootMismatch === true) {
        json(response, 422, { code: "MERKLE_ROOT_MISMATCH" });
        return;
      }
      if (scenario.decryptionFails === true) {
        json(response, 422, { code: "DECRYPTION_FAILED" });
        return;
      }
      const operation: FixtureRecoveryOperation = {
        operationId: randomUUID(),
        centerId,
        snapshotId,
        snapshotVersion: snapshot.snapshotVersion,
        snapshotStatus: snapshot.snapshotStatus,
        target,
        merkleRoot: snapshot.merkleRoot,
        plaintextHash: snapshot.plaintextHash,
        ciphertextHash: snapshot.ciphertextHash,
        anchor: {
          batchSequence: "1",
          anchorSlot: "412346000",
          transactionSignature: SIGNATURE,
          merkleRoot: snapshot.merkleRoot,
          finalizedAt: new Date(1_800_000_100_000).toISOString(),
        },
        state: "AWAITING_APPROVAL",
        failureCode: null,
        approvedBy: null,
        approval: null,
        restoredTarget: null,
      };
      recoveryOperations.push(operation);
      record("RECOVERY_CHECKS_PASSED", session, {
        recoveryOperationId: operation.operationId,
        centerId,
        snapshotId,
        target,
        merkleRoot: operation.merkleRoot,
        ciphertextHash: operation.ciphertextHash,
        plaintextHash: operation.plaintextHash,
        shareThreshold: "3-of-5",
      });
      json(response, 201, recoveryOperationBody(operation));
      return;
    }
    const recoveryRoute = /^\/v1\/admin\/recovery\/(?:operations\/)?([0-9a-f-]{36})(?:\/(approve|approval|restore))?$/.exec(url.pathname);
    if (recoveryRoute !== null) {
      const operation = recoveryOperations.find((candidate) => candidate.operationId === recoveryRoute[1]);
      if (operation === undefined) { json(response, 404, { code: "RECOVERY_OPERATION_NOT_FOUND" }); return; }
      const action = recoveryRoute[2];
      if (method === "GET" && action === undefined) {
        json(response, 200, recoveryOperationBody(operation));
        return;
      }
      if (method === "POST" && (action === "approve" || action === "approval")) {
        if (session.role !== "chief_admin") { json(response, 403, { code: "ROLE_FORBIDDEN" }); return; }
        if (operation.state === "APPROVED" || operation.state === "RESTORED") {
          json(response, 200, recoveryOperationBody(operation, true));
          return;
        }
        if (operation.state !== "AWAITING_APPROVAL") {
          json(response, 409, { code: "RESTORE_APPROVAL_INVALID_STATE" });
          return;
        }
        const body = await readBody(request);
        if (
          (body?.snapshotId !== undefined && body.snapshotId !== operation.snapshotId) ||
          (body?.merkleRoot !== undefined && body.merkleRoot !== operation.merkleRoot) ||
          (body?.target !== undefined && body.target !== operation.target)
        ) {
          operation.state = "FAILED";
          operation.failureCode = "RESTORE_BINDING_MISMATCH";
          record("RECOVERY_FAILED", session, { recoveryOperationId: operation.operationId, code: operation.failureCode });
          json(response, 409, { code: operation.failureCode });
          return;
        }
        const approvalId = randomUUID();
        const approvalDigest = createHash("sha256")
          .update([operation.operationId, operation.snapshotId, operation.merkleRoot, operation.target].join("\0"))
          .digest("hex");
        operation.state = "APPROVED";
        operation.approvedBy = session.username;
        operation.approval = {
          approvalId,
          snapshotId: operation.snapshotId,
          merkleRoot: operation.merkleRoot,
          target: operation.target,
          approvalDigest,
          approvalSignature: createHash("sha256").update(`signature:${approvalDigest}`).digest("base64url"),
          signedBy: session.username,
          signedAt: new Date(1_800_000_200_000).toISOString(),
        };
        record("RESTORE_APPROVED", session, {
          recoveryOperationId: operation.operationId,
          approvalId,
          snapshotId: operation.snapshotId,
          merkleRoot: operation.merkleRoot,
          target: operation.target,
          approvalDigest,
        });
        json(response, 201, recoveryOperationBody(operation));
        return;
      }
      if (method === "POST" && action === "restore") {
        if (session.role !== "operator") { json(response, 403, { code: "ROLE_FORBIDDEN" }); return; }
        if (operation.state === "RESTORED") {
          json(response, 200, recoveryOperationBody(operation, true));
          return;
        }
        if (operation.state !== "APPROVED") {
          json(response, 409, { code: "RESTORE_APPROVAL_REQUIRED" });
          return;
        }
        if (scenario.rootMismatch === true) {
          operation.state = "FAILED";
          operation.failureCode = "RECOVERY_ANCHOR_CHANGED";
          record("RECOVERY_FAILED", session, { recoveryOperationId: operation.operationId, code: operation.failureCode });
          json(response, 409, { code: operation.failureCode });
          return;
        }
        operation.state = "RESTORED";
        operation.restoredTarget = {
          targetId: operation.target,
          stateSummary: {
            records: 2,
            recordVersions: 2,
            certificatePackages: 0,
            qrMetadata: 0,
            proofs: 0,
            roots: 1,
            manifests: 1,
            anchorReferences: 1,
            operationHistory: timeline.length,
          },
          restoredAt: fixtureNow(),
          plaintextCleared: true,
        };
        record("RESTORE_COMPLETED", session, {
          recoveryOperationId: operation.operationId,
          snapshotId: operation.snapshotId,
          merkleRoot: operation.merkleRoot,
          target: operation.target,
          plaintextCleared: true,
        });
        json(response, 201, recoveryOperationBody(operation));
        return;
      }
    }
    if ((url.pathname === "/v1/admin/backup-centers" || url.pathname === "/v1/admin/snapshots") && method === "GET") {
      json(response, 200, backupOverview());
      return;
    }
    if (url.pathname === "/v1/admin/backup-centers" && method === "POST") {
      if (session.role !== "operator") { json(response, 403, { code: "ROLE_FORBIDDEN" }); return; }
      const body = await readBody(request);
      if (body?.scope !== undefined && body.scope !== "LOCAL") {
        json(response, 400, { code: "EXTERNAL_BACKUP_CENTER_UNSUPPORTED" });
        return;
      }
      const ordinal = centers.length + 1;
      const suffix = randomUUID().replaceAll("-", "");
      const center: FixtureCenter = {
        centerId: `BACKUPCENTER-${ordinal}`,
        name: typeof body?.name === "string" && body.name.length > 0 ? body.name : `Local BackupCenter ${String(ordinal).padStart(2, "0")}`,
        volumeName: `onelayer-backup-volume-${suffix}`,
        credentialReference: `onelayer-backup-credential-${suffix}`,
        credentialVersion: "credential-v1",
        folders: [],
      };
      centers.push(center);
      record("BACKUP_CENTER_CREATED", session, { centerId: center.centerId, scope: "LOCAL" });
      json(response, 201, backupCenterBody(center));
      return;
    }
    if (
      (url.pathname === "/v1/admin/snapshots" || url.pathname === "/v1/admin/snapshots/refresh" ||
        url.pathname === "/v1/admin/backup-centers/refresh") && method === "POST"
    ) {
      if (session.role !== "operator") { json(response, 403, { code: "ROLE_FORBIDDEN" }); return; }
      const idempotencyKey = request.headers["idempotency-key"];
      if (typeof idempotencyKey !== "string") { json(response, 400, { code: "IDEMPOTENCYKEY_INVALID" }); return; }
      const existingId = backupIdempotency.get(idempotencyKey);
      if (existingId !== undefined) {
        const existing = snapshots.find((candidate) => candidate.operationId === existingId);
        if (existing !== undefined) { json(response, 200, backupOperationBody(existing, true)); return; }
      }
      const snapshotId = randomUUID();
      const snapshotKey = snapshotId.replaceAll("-", "");
      const snapshot: FixtureSnapshot = {
        snapshotId,
        snapshotVersion: String(snapshots.length + 1),
        snapshotStatus: scenario.snapshotFinalized === false ? "NON_FINALIZED" : "FINALIZED",
        plaintextHash: createHash("sha256").update(`plaintext:${snapshotId}`).digest("hex"),
        ciphertextHash: createHash("sha256").update(`ciphertext:${snapshotId}`).digest("hex"),
        merkleRoot: MERKLE_ROOT,
        createdAt: fixtureNow(),
        operationId: randomUUID(),
      };
      for (const center of centers) {
        const copied = centerAvailable(center.centerId);
        center.folders.push({
          snapshotId: snapshot.snapshotId,
          snapshotVersion: snapshot.snapshotVersion,
          objectKey: `snapshots/${snapshotKey}/snapshot-package-v1.cbor`,
          status: copied ? "COPIED" : "PENDING_RETRY",
          snapshotStatus: snapshot.snapshotStatus,
          plaintextHash: snapshot.plaintextHash,
          ciphertextHash: snapshot.ciphertextHash,
          merkleRoot: snapshot.merkleRoot,
          lastError: copied ? null : "CENTER_UNAVAILABLE",
          createdAt: snapshot.createdAt,
          verifiedAt: copied ? snapshot.createdAt : null,
        });
        applyRetention(center);
      }
      snapshots.push(snapshot);
      backupIdempotency.set(idempotencyKey, snapshot.operationId);
      record("SNAPSHOT_CREATED", session, {
        operationId: snapshot.operationId,
        snapshotId: snapshot.snapshotId,
        snapshotVersion: snapshot.snapshotVersion,
        packageFormat: "SnapshotPackageV1",
        ciphertextHash: snapshot.ciphertextHash,
      });
      json(response, 201, backupOperationBody(snapshot));
      return;
    }
    const retryPath = /^\/v1\/admin\/snapshots\/([0-9a-f-]{36})\/retry$/.exec(url.pathname);
    if (retryPath !== null && method === "POST") {
      if (session.role !== "operator") { json(response, 403, { code: "ROLE_FORBIDDEN" }); return; }
      const snapshot = snapshots.find((candidate) => candidate.snapshotId === retryPath[1]);
      if (snapshot === undefined) { json(response, 404, { code: "SNAPSHOT_NOT_FOUND" }); return; }
      for (const center of centers) {
        const folder = center.folders.find((candidate) => candidate.snapshotId === snapshot.snapshotId);
        if (folder === undefined || folder.status === "COPIED") continue;
        if (centerAvailable(center.centerId)) {
          folder.status = "COPIED";
          folder.lastError = null;
          folder.verifiedAt = fixtureNow();
        } else {
          folder.status = "PENDING_RETRY";
          folder.lastError = "CENTER_UNAVAILABLE";
        }
      }
      record("SNAPSHOT_REPLICA_RETRIED", session, { snapshotId: snapshot.snapshotId });
      json(response, 200, backupOperationBody(snapshot));
      return;
    }
    if (
      method === "DELETE" &&
      (/^\/v1\/admin\/(?:snapshots|backup-centers)(?:\/|$)/.test(url.pathname))
    ) {
      json(response, 403, { code: "BACKUP_DELETE_FORBIDDEN" });
      return;
    }
    if (url.pathname === "/v1/admin/records" && method === "GET") {
      json(response, 200, { schemaId: SCHEMA_ID, records });
      return;
    }
    if (url.pathname === "/v1/admin/records" && method === "POST") {
      if (session.role !== "operator") { json(response, 403, { code: "ROLE_FORBIDDEN" }); return; }
      const body = await readBody(request);
      const outcome = upsert(body);
      if (outcome === null) { json(response, 422, { code: "FIELD_REQUIRED_MISSING", path: "cadastralNumber" }); return; }
      record("RECORD_UPSERTED", session, { internalRecordId: outcome.internalRecordId });
      json(response, 201, outcome);
      return;
    }
    if (url.pathname === "/v1/admin/records/import" && method === "POST") {
      if (session.role !== "operator") { json(response, 403, { code: "ROLE_FORBIDDEN" }); return; }
      const body = await readBody(request);
      const report = parseImport(body);
      if (!body?.dryRun) {
        for (const entry of report.accepted) {
          const applied = upsert({ internalRecordId: entry.internalRecordId, fields: fieldMap(entry) });
          if (applied !== null) report.applied.push({ row: entry.row, ...applied });
        }
        if (report.accepted.length > 0) record("RECORDS_IMPORTED", session, { accepted: report.accepted.length });
      }
      json(response, body?.dryRun ? 200 : report.accepted.length > 0 ? 201 : 422, {
        schemaId: SCHEMA_ID,
        dryRun: body?.dryRun === true,
        ...report,
      });
      return;
    }
    const recordPath = /^\/v1\/admin\/records\/(SYNTHETIC-[1-9][0-9]*)$/.exec(url.pathname);
    if (recordPath !== null && method === "GET") {
      const row = records.find((candidate) => candidate.internalRecordId === recordPath[1]);
      if (row === undefined) { json(response, 404, { code: "RECORD_NOT_FOUND" }); return; }
      const fields = [{ path: "status", type: "text", value: row.status }, ...row.fields];
      json(response, 200, {
        internalRecordId: row.internalRecordId,
        recordVersion: row.recordVersion,
        sourceCursor: row.sourceCursor,
        status: row.status,
        origin: row.origin,
        schemaId: row.schemaId,
        recordIdCommitment: "11".repeat(32),
        fieldRoot: "dd".repeat(32),
        recordCommitment: "ee".repeat(32),
        batchLeafHash: "ff".repeat(32),
        fields: fields.map((field, index) => ({
          path: field.path,
          value: field.value,
          fieldCommitment: `${index + 1}`.repeat(64).slice(0, 64),
          fieldLeafIndex: index,
        })),
        certificates: certificates
          .filter((certificate) => certificate.internalRecordId === row.internalRecordId)
          .map((certificate) => ({
            certificateId: certificate.certificateId,
            status: certificate.status,
            issuedAt: certificate.issuedAt,
            disclosureMode: certificate.disclosureMode,
            disclosedPaths: certificate.disclosedPaths,
            recordVersion: certificate.recordVersion,
          })),
      });
      return;
    }
    if (url.pathname === "/v1/admin/preview" && method === "GET") {
      json(response, 200, {
        registryId: "gov.registry.land",
        batchSequence: "1",
        registryVersion: "1",
        cursorStart: "1",
        cursorEnd: "2",
        leafCount: records.length,
        merkleRoot: MERKLE_ROOT,
        manifestHash: MANIFEST_HASH,
        previousAnchorHash: PREVIOUS_ANCHOR,
        records: records.map((row, index) => previewRecord(row, index)),
      });
      return;
    }
    if (url.pathname === "/v1/admin/certificates" && method === "GET") {
      json(response, 200, { certificates });
      return;
    }
    if (url.pathname === "/v1/admin/timeline" && method === "GET") {
      json(response, 200, { events: timeline });
      return;
    }
    if (url.pathname === "/v1/admin/publish-intents" && method === "POST") {
      if (session.role !== "operator") { json(response, 403, { code: "ROLE_FORBIDDEN" }); return; }
      const key = request.headers["idempotency-key"];
      if (typeof key !== "string") { json(response, 400, { code: "IDEMPOTENCYKEY_INVALID" }); return; }
      const body = await readBody(request);
      if (body?.cluster !== "solana:devnet") { json(response, 400, { code: "CLUSTER_INVALID" }); return; }
      const known = idempotency.get(key);
      if (known !== undefined) {
        json(response, 200, { ...intents.get(known), replayed: true });
        return;
      }
      const intentId = randomUUID();
      const intent: Intent = {
        intentId,
        state: scenario.simulationFails === true ? "SIMULATION_FAILED" : "SIMULATED",
        batchSequence: "1",
        intentHash: createHash("sha256").update(intentId).digest("hex"),
        review: {
          cluster: "solana:devnet",
          programId: PROGRAM_ID,
          configPda: "3Z2sBGBrLcuvbxgUjqPmMKDgUKtcHkjEG5FhXpxJdyLA",
          rolePda: "8bFHmM6RGJ8P4WNbnDMFyBGKcH1xkbSfzaFCS4YDqSme",
          segmentPda: SEGMENT_PDA,
          segmentIndex: 0,
          dayUtc: 20_665,
          feePayer: body?.operator ?? WALLET_ADDRESS,
          merkleRoot: MERKLE_ROOT,
          manifestHash: MANIFEST_HASH,
          previousAnchorHash: PREVIOUS_ANCHOR,
          leafCount: records.length,
          records: records.map((row, index) => previewRecord(row, index)),
          accounts: [
            { address: "3Z2sBGBrLcuvbxgUjqPmMKDgUKtcHkjEG5FhXpxJdyLA", role: "writable" },
            { address: "8bFHmM6RGJ8P4WNbnDMFyBGKcH1xkbSfzaFCS4YDqSme", role: "readonly" },
            { address: String(body?.operator ?? WALLET_ADDRESS), role: "signer" },
            { address: SEGMENT_PDA, role: "writable" },
          ],
          instructionData: "AAECAwQ=",
          transactionBase64: Buffer.from("unsigned-fixture-transaction").toString("base64"),
          simulation: scenario.simulationFails === true
            ? { ok: false, error: "AccountNotFound", unitsConsumed: null }
            : { ok: true, error: null, unitsConsumed: 24_150 },
        },
        recentBlockhash: "6vSnGCBTx1nq5vFvSDgFTQBaX2eqicE4b4nsAxrhVJNU",
        lastValidBlockHeight: "1000",
        expiresAt: new Date(1_800_000_090_000).toISOString(),
        transactionSignature: null,
        anchorSlot: null,
        certificateId: null,
        failureCode: null,
        simulationLogs: ["Program log: publish_anchor", "Program consumed 24150 compute units"],
      };
      intents.set(intentId, intent);
      idempotency.set(key, intentId);
      record("BATCH_SIMULATED", session, { batchSequence: "1", merkleRoot: MERKLE_ROOT });
      json(response, scenario.simulationFails === true ? 422 : 201, intent);
      return;
    }

    const intentRoute = /^\/v1\/admin\/publish-intents\/([0-9a-f-]{36})(\/[a-z]+)?$/.exec(url.pathname);
    if (intentRoute !== null) {
      const intent = intents.get(intentRoute[1]);
      if (intent === undefined) { json(response, 404, { code: "INTENT_NOT_FOUND" }); return; }
      const action = intentRoute[2];
      if (method === "GET" && action === undefined) { json(response, 200, intent); return; }
      if (session.role !== "operator") { json(response, 403, { code: "ROLE_FORBIDDEN" }); return; }
      if (action === "/signature") {
        const body = await readBody(request);
        if (scenario.blockhashExpired === true) {
          intent.state = "EXPIRED";
          intent.failureCode = "BLOCKHASH_EXPIRED";
          json(response, 200, intent);
          return;
        }
        if (typeof body?.signedTransactionBase64 !== "string") {
          json(response, 422, { code: "SIGNED_TRANSACTION_MALFORMED" });
          return;
        }
        intent.state = "SUBMITTED";
        intent.transactionSignature = SIGNATURE;
        record("TRANSACTION_SUBMITTED", session, { signature: SIGNATURE });
        json(response, 200, intent);
        return;
      }
      if (action === "/reconciliation") {
        if (intent.state === "SUBMITTED") {
          intent.state = "FINALIZED";
          intent.anchorSlot = "412346000";
          record("ANCHOR_FINALIZED", session, { slot: "412346000" });
        }
        json(response, 200, intent);
        return;
      }
      if (action === "/rejection") {
        intent.state = "SIGNING_REJECTED";
        intent.failureCode = "WALLET_REJECTED";
        json(response, 200, intent);
        return;
      }
      if (action === "/certificate") {
        if (intent.state !== "FINALIZED" && intent.state !== "ISSUED") {
          json(response, 409, { code: "ANCHOR_NOT_FINALIZED" });
          return;
        }
        if (!registryIsWorking()) { json(response, 409, { code: "REGISTRY_PAUSED" }); return; }
        const body = await readBody(request);
        const certificateId = "0".repeat(31) + "1";
        const internalRecordId = String(body?.internalRecordId ?? "SYNTHETIC-1");
        const row = records.find((candidate) => candidate.internalRecordId === internalRecordId);
        const available = ["status", ...(row?.fields ?? []).map((field) => field.path)];
        const requested = Array.isArray(body?.disclosedPaths) ? (body.disclosedPaths as string[]) : available;
        const selective = requested.length < available.length;
        intent.state = "ISSUED";
        intent.certificateId = certificateId;
        const issued = certificates.find((certificate) => certificate.certificateId === certificateId);
        if (issued !== undefined) {
          // The fixture keeps one deterministic certificate ID, so a later
          // issuance replaces the disclosure instead of adding a second row.
          issued.internalRecordId = internalRecordId;
          issued.recordVersion = row?.recordVersion ?? "1";
          issued.disclosureMode = selective ? "SELECTIVE_FIELDS" : "FULL_RECORD";
          issued.disclosedPaths = [...requested].sort();
        } else {
          certificates.push({
            certificateId,
            batchSequence: "1",
            status: "ACTIVE",
            issuedAt: new Date(1_800_000_100_000).toISOString(),
            qrUrl: `${webBaseUrl}/c/${certificateId}?h=${qrHash(certificateId)}`,
            internalRecordId,
            recordVersion: row?.recordVersion ?? "1",
            certificateHash: certificateHashOf(certificateId),
            disclosureMode: selective ? "SELECTIVE_FIELDS" : "FULL_RECORD",
            disclosedPaths: [...requested].sort(),
          });
        }
        record("CERTIFICATE_ISSUED", session, { certificateId });
        json(response, 201, {
          intentId: intent.intentId,
          state: "ISSUED",
          certificateId,
          certificateHash: certificateHashOf(certificateId),
          qrUrl: `${webBaseUrl}/c/${certificateId}?h=${qrHash(certificateId)}`,
          transactionSignature: SIGNATURE,
          anchorSlot: "412346000",
          explorerUrl: `https://explorer.solana.com/tx/${SIGNATURE}?cluster=devnet`,
          disclosureMode: selective ? "SELECTIVE_FIELDS" : "FULL_RECORD",
          disclosedPaths: [...requested].sort(),
          fieldCount: available.length,
        });
        return;
      }
    }

    json(response, 404, { code: "NOT_FOUND" });
  }

  return {
    server,
    port: () => (server.address() as { port: number }).port,
  };
}

export { certificateHashOf, qrHash };
