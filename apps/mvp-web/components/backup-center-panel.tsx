"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { admin, ApiError } from "../lib/api";
import { useAdminSession } from "./admin-session";
import { describeBackup, describeRecovery, Field, StatusBadge } from "./status";

interface Folder {
  folderId: string;
  objectKey: string;
  snapshotId: string;
  snapshotVersion: string;
  status: string;
  snapshotStatus: string;
  plaintextHash: string;
  ciphertextHash: string;
  merkleRoot: string;
  lastError: string | null;
  createdAt: string | null;
  verifiedAt: string | null;
}

interface Center {
  centerId: string;
  name: string;
  scope: string;
  endpoint: string;
  volumeName: string;
  credentialVersion: string;
  credentials: { reference: string; version: string };
  active: boolean;
  health: { status: string; available: boolean; checkedAt: string };
  folders: Folder[];
  replicaStatus: { copied: number; pendingRetry: number; failed: number; total: number };
  retiredFolderCount: number;
}

interface Overview {
  retentionWindow: number;
  packageFormat: string;
  centers: Center[];
  snapshots: Array<{
    snapshotId: string;
    snapshotVersion: string;
    snapshotStatus: string;
    merkleRoot: string;
    ciphertextHash: string;
    replicas: Array<{ centerId: string; copyStatus: string }>;
  }>;
}

interface RecoveryOperation {
  recoveryOperationId: string;
  operationId: string;
  centerId: string;
  snapshotId: string;
  snapshotVersion: string;
  snapshotStatus: string;
  target: string;
  state: "AWAITING_APPROVAL" | "APPROVED" | "VALIDATED" | "RESTORED" | "FAILED";
  merkleRoot: string;
  plaintextHash: string;
  ciphertextHash: string;
  anchor: {
    batchSequence: string;
    anchorSlot: string;
    transactionSignature: string | null;
    merkleRoot: string;
    finalizedAt: string;
  };
  validation: {
    threshold: string;
    ciphertextHash: string;
    plaintextHash: string;
    merkleRoot: string;
  } | null;
  failureCode: string | null;
  approval: {
    approvalId: string;
    snapshotId: string;
    merkleRoot: string;
    target: string;
    approvalDigest: string;
    approvalSignature: string;
    signedBy: string;
    signedAt: string;
  } | null;
  restoredTarget: {
    targetId: string;
    stateSummary: Record<string, number>;
    restoredAt: string;
    plaintextCleared: boolean;
  } | null;
}

function short(value: string): string {
  return value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-10)}` : value;
}

function freshOperationKey(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

export function BackupCenterPanel(): ReactNode {
  const { session } = useAdminSession();
  const [overview, setOverview] = useState<Overview | null>(null);
  const [operations, setOperations] = useState<RecoveryOperation[]>([]);
  const [recovery, setRecovery] = useState<RecoveryOperation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [centerName, setCenterName] = useState("");
  const [selectedCenterId, setSelectedCenterId] = useState("");
  const [selectedSnapshotId, setSelectedSnapshotId] = useState("");
  const [target, setTarget] = useState("local-demo-target");
  const [shares, setShares] = useState<[string, string, string]>(["", "", ""]);
  const operationKey = useRef<string>(freshOperationKey());
  const readOnly = session?.role !== "operator";

  const selectedCenter = overview?.centers.find((center) => center.centerId === selectedCenterId) ?? overview?.centers[0];
  const selectedFolder = selectedCenter?.folders.find((folder) => folder.snapshotId === selectedSnapshotId) ?? selectedCenter?.folders[0];

  async function loadAll(): Promise<void> {
    const [nextOverview, nextOperations] = await Promise.all([
      admin("/backup-centers") as Promise<Overview>,
      admin("/recovery/operations") as Promise<{ operations: RecoveryOperation[] }>,
    ]);
    setOverview(nextOverview);
    setOperations(nextOperations.operations);
    setRecovery((current) => {
      const currentId = current?.operationId;
      return nextOperations.operations.find((operation) => operation.operationId === currentId) ??
        nextOperations.operations[0] ?? current;
    });
  }

  useEffect(() => {
    void loadAll().catch((cause: unknown) => setError(cause instanceof ApiError ? cause.code : "LOAD_FAILED"));
  }, []);

  useEffect(() => {
    if (overview === null || overview.centers.length === 0) return;
    setSelectedCenterId((current) => overview.centers.some((center) => center.centerId === current)
      ? current
      : overview.centers[0].centerId);
  }, [overview]);

  useEffect(() => {
    if (selectedCenter === undefined) return;
    setSelectedSnapshotId((current) => selectedCenter.folders.some((folder) => folder.snapshotId === current)
      ? current
      : selectedCenter.folders[0]?.snapshotId ?? "");
  }, [selectedCenter]);

  async function run(action: () => Promise<void>): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.code : "REQUEST_FAILED");
    } finally {
      setBusy(false);
    }
  }

  async function refreshBackups(): Promise<void> {
    if (session === null) return;
    await admin("/snapshots/refresh", {
      method: "POST",
      csrfToken: session.csrfToken,
      idempotencyKey: operationKey.current,
    });
    operationKey.current = freshOperationKey();
    await loadAll();
  }

  async function prepareRecovery(): Promise<void> {
    if (session === null || selectedCenter === undefined || selectedFolder === undefined) return;
    try {
      const result = await admin("/recovery/prepare", {
        method: "POST",
        csrfToken: session.csrfToken,
        body: {
          centerId: selectedCenter.centerId,
          snapshotId: selectedFolder.snapshotId,
          target: target.trim(),
          recoveryShares: shares.map((share) => share.trim()).filter((share) => share.length > 0),
        },
      }) as RecoveryOperation;
      setRecovery(result);
      await loadAll();
    } finally {
      // Clear the masked inputs on both success and failure. The browser never
      // retains shares in storage, the operation response or the timeline.
      setShares(["", "", ""]);
    }
  }

  async function approveRecovery(): Promise<void> {
    if (session === null || recovery === null) return;
    const result = await admin(`/recovery/operations/${recovery.operationId}/approve`, {
      method: "POST",
      csrfToken: session.csrfToken,
      body: {
        snapshotId: recovery.snapshotId,
        merkleRoot: recovery.merkleRoot,
        target: recovery.target,
      },
    }) as RecoveryOperation;
    setRecovery(result);
    await loadAll();
  }

  async function restoreRecovery(): Promise<void> {
    if (session === null || recovery === null) return;
    const result = await admin(`/recovery/operations/${recovery.operationId}/restore`, {
      method: "POST",
      csrfToken: session.csrfToken,
    }) as RecoveryOperation;
    setRecovery(result);
    await loadAll();
  }

  return (
    <>
      <section className="ol-card" data-testid="backup-center-panel">
        <h2>Backup Center</h2>
        <p className="ol-muted">
          Bounded local control plane. Centers expose only local volume and credential references;
          private credentials, Recovery Shares and plaintext never enter the browser response.
        </p>
        {error !== null ? <p className="ol-error" data-testid="backup-error">{error}</p> : null}
        <dl className="ol-grid" data-testid="backup-summary">
          <Field label="Centers" value={<span data-testid="backup-center-count">{overview?.centers.length ?? "…"}</span>} />
          <Field label="Retention Window" value={overview?.retentionWindow ?? "…"} />
          <Field label="Package" value={overview?.packageFormat ?? "SnapshotPackageV1"} />
          <Field label="Snapshots" value={<span data-testid="snapshot-count">{overview?.snapshots.length ?? "…"}</span>} />
        </dl>
        <p>
          <button
            type="button"
            data-variant="primary"
            data-testid="refresh-backups"
            disabled={readOnly || busy}
            onClick={() => void run(refreshBackups)}
          >
            Refresh copies
          </button>
        </p>
      </section>

      <section className="ol-card">
        <h2>Local BackupCenters</h2>
        <div data-testid="backup-centers">
          {overview?.centers.map((center) => (
            <article className="ol-subcard" key={center.centerId} data-testid={`backup-center-${center.centerId}`}>
              <h3>{center.name}</h3>
              <p><StatusBadge status={describeBackup(center.health.status)} testId={`health-${center.centerId}`} /></p>
              <dl className="ol-grid">
                <Field label="Center ID" value={center.centerId} />
                <Field label="Scope" value={center.scope} />
                <Field label="Volume" value={center.volumeName} />
                <Field label="Credential version" value={center.credentials.version ?? center.credentialVersion} />
                <Field label="Credential reference" value={center.credentials.reference} />
                <Field label="Replica status" value={`${center.replicaStatus.copied} copied · ${center.replicaStatus.pendingRetry} pending · ${center.replicaStatus.failed} errors`} />
                <Field label="Retired folders" value={center.retiredFolderCount ?? 0} />
              </dl>
              <h4>Immutable folders</h4>
              {center.folders.length === 0 ? <p className="ol-muted">No snapshot replicas yet.</p> : (
                <div className="ol-stack" data-testid={`folders-${center.centerId}`}>
                  {center.folders.map((folder) => (
                    <div className="ol-subcard" key={`${center.centerId}-${folder.snapshotId}`}>
                      <p><StatusBadge status={describeBackup(folder.status)} testId={`replica-${center.centerId}-${folder.snapshotId}`} /></p>
                      <dl className="ol-grid">
                        <Field label="Snapshot" value={`v${folder.snapshotVersion} · ${short(folder.snapshotId)}`} />
                        <Field label="Folder" value={folder.objectKey} />
                        <Field label="Snapshot status" value={folder.snapshotStatus} />
                        <Field label="Ciphertext hash" value={short(folder.ciphertextHash)} />
                        <Field label="Merkle root" value={short(folder.merkleRoot)} />
                      </dl>
                      {folder.lastError !== null ? <p className="ol-error">{folder.lastError}</p> : null}
                      {folder.status !== "COPIED" && !readOnly ? (
                        <button
                          type="button"
                          data-testid={`retry-${center.centerId}-${folder.snapshotId}`}
                          disabled={busy}
                          onClick={() => void run(async () => {
                            if (session === null) return;
                            await admin(`/snapshots/${folder.snapshotId}/retry`, {
                              method: "POST",
                              csrfToken: session.csrfToken,
                            });
                            await loadAll();
                          })}
                        >
                          Retry this replica
                        </button>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </article>
          ))}
        </div>
        {overview === null ? <p role="status">Loading BackupCenters…</p> : null}
      </section>

      <section className="ol-card" data-testid="recovery-panel">
        <h2>Demo Recovery Validation</h2>
        <p className="ol-muted">
          Recovery Shares are entered out-of-band into masked fields, used once to reconstruct the
          operation KEK, and cleared before this response is rendered. No share, plaintext or private
          key is returned to the browser or timeline.
        </p>
        <p className="ol-muted">This demo validates approved recovery material. A completed recovery requires imported and verified target data.</p>

        {session?.role === "operator" ? (
          <form onSubmit={(event) => {
            event.preventDefault();
            void run(prepareRecovery);
          }}>
            <div className="ol-grid">
              <label className="ol-field">
                <span className="ol-label">BackupCenter</span>
                <select
                  value={selectedCenter?.centerId ?? ""}
                  onChange={(event) => {
                    setSelectedCenterId(event.target.value);
                    setSelectedSnapshotId("");
                  }}
                  disabled={busy || overview === null}
                  data-testid="recovery-center"
                >
                  {overview?.centers.map((center) => <option key={center.centerId} value={center.centerId}>{center.name}</option>)}
                </select>
              </label>
              <label className="ol-field">
                <span className="ol-label">Snapshot folder</span>
                <select
                  value={selectedFolder?.snapshotId ?? ""}
                  onChange={(event) => setSelectedSnapshotId(event.target.value)}
                  disabled={busy || selectedCenter === undefined || selectedCenter.folders.length === 0}
                  data-testid="recovery-snapshot"
                >
                  {selectedCenter?.folders.map((folder) => (
                    <option key={folder.snapshotId} value={folder.snapshotId}>
                      v{folder.snapshotVersion} · {folder.status} · {short(folder.snapshotId)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="ol-field">
                <span className="ol-label">Bounded target</span>
                <input value={target} onChange={(event) => setTarget(event.target.value)} disabled={busy} data-testid="recovery-target" />
              </label>
            </div>
            <div className="ol-grid">
              {shares.map((share, index) => (
                <label className="ol-field" key={`share-${index + 1}`}>
                  <span className="ol-label">Recovery Share {index + 1} of 3</span>
                  <input
                    type="password"
                    autoComplete="off"
                    value={share}
                    onChange={(event) => setShares((current) => {
                      const next: [string, string, string] = [...current] as [string, string, string];
                      next[index] = event.target.value;
                      return next;
                    })}
                    disabled={busy}
                    data-testid={`recovery-share-${index + 1}`}
                  />
                </label>
              ))}
            </div>
            <p>
              <button type="submit" data-variant="primary" data-testid="prepare-recovery" disabled={busy || selectedFolder === undefined}>
                Check shares and request Restore Approval
              </button>
            </p>
          </form>
        ) : (
          <p className="ol-muted" data-testid="recovery-readonly">
            {session?.role === "chief_admin"
              ? "Chief Admin can sign an approval only after the operator's threshold and integrity checks pass."
              : "Auditor access is read-only; recovery preparation and approval are unavailable."}
          </p>
        )}

        {recovery !== null ? (
          <article className="ol-subcard" data-testid="recovery-operation">
            <p><StatusBadge status={describeRecovery(recovery.state)} testId="recovery-state" /></p>
            <dl className="ol-grid">
              <Field label="Operation" value={<span data-testid="recovery-operation-id">{recovery.operationId}</span>} />
              <Field label="Center" value={recovery.centerId} />
              <Field label="Snapshot" value={`v${recovery.snapshotVersion} · ${short(recovery.snapshotId)}`} />
              <Field label="Target" value={recovery.target} />
              <Field label="Selected anchor batch" value={<span data-testid="recovery-anchor-batch">{recovery.anchor.batchSequence}</span>} />
              <Field label="Selected anchor slot" value={recovery.anchor.anchorSlot} />
              <Field label="Selected Merkle root" value={<span data-testid="recovery-anchor-root">{recovery.anchor.merkleRoot}</span>} />
              <Field label="Threshold" value={recovery.validation?.threshold ?? "—"} />
              <Field label="Ciphertext check" value={recovery.validation?.ciphertextHash ?? "—"} />
              <Field label="Plaintext check" value={recovery.validation?.plaintextHash ?? "—"} />
              <Field label="Root check" value={recovery.validation?.merkleRoot ?? "—"} />
            </dl>
            {recovery.failureCode !== null ? <p className="ol-error" data-testid="recovery-failure">{recovery.failureCode}</p> : null}
            {session?.role === "chief_admin" && recovery.state === "AWAITING_APPROVAL" ? (
              <button type="button" data-variant="primary" data-testid="approve-restore" disabled={busy} onClick={() => void run(approveRecovery)}>
                Approve exact snapshot, root and target
              </button>
            ) : null}
            {session?.role === "operator" && recovery.state === "APPROVED" ? (
              <button type="button" data-variant="primary" data-testid="restore-recovery" disabled={busy} onClick={() => void run(restoreRecovery)}>
                Validate approved recovery material
              </button>
            ) : null}
            {recovery.state === "VALIDATED" ? (
              <p className="ol-muted" data-testid="recovery-material-validated">
                Recovery material validated; target import remains pending. Operation plaintext cleared.
              </p>
            ) : null}
            {recovery.state === "RESTORED" && recovery.restoredTarget !== null ? (
              <p className="ol-muted" data-testid="recovery-plaintext-cleared">
                Restore completed for <code>{recovery.restoredTarget.targetId}</code>; operation plaintext cleared.
              </p>
            ) : null}
          </article>
        ) : null}

        {operations.length > 0 ? (
          <div className="ol-stack" data-testid="recovery-history">
            <h3>Recovery operation history</h3>
            {operations.map((operation) => (
              <button
                type="button"
                key={operation.operationId}
                data-testid={`recovery-history-${operation.operationId}`}
                onClick={() => setRecovery(operation)}
              >
                {operation.state} · {short(operation.operationId)} · {short(operation.snapshotId)}
              </button>
            ))}
          </div>
        ) : null}
      </section>

      <section className="ol-card">
        <h2>Create local BackupCenter</h2>
        <p className="ol-muted">Only local bounded centers can be added in this MVP; external production registration is unavailable.</p>
        <form onSubmit={(event) => {
          event.preventDefault();
          void run(async () => {
            if (session === null) return;
            await admin("/backup-centers", {
              method: "POST",
              body: centerName.trim().length === 0 ? {} : { name: centerName.trim() },
              csrfToken: session.csrfToken,
            });
            setCenterName("");
            await loadAll();
          });
        }}>
          <label className="ol-field">
            <span className="ol-label">Optional name</span>
            <input value={centerName} onChange={(event) => setCenterName(event.target.value)} disabled={readOnly || busy} data-testid="backup-center-name" />
          </label>
          <p>
            <button type="submit" disabled={readOnly || busy} data-testid="create-backup-center">Create local center</button>
          </p>
        </form>
      </section>
    </>
  );
}
