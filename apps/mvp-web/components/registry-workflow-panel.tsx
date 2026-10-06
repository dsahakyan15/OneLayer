"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import {
  ApiError,
  workflowAcknowledgeAttempt,
  workflowAction,
  workflowActionPath,
  workflowCancelAttempt,
  workflowCreateDraft,
  workflowCreatePath,
  workflowListDrafts,
  workflowListAttempts,
  workflowPrepareAttempt,
  workflowReadDraft,
  type WorkflowAction,
  type WorkflowAttempt,
} from "../lib/api";
import { hasPermission, roleLabel, useAdminSession } from "./admin-session";
import { Field, StatusBadge, type StatusDescriptor } from "./status";

/** Draft states of the workflow contract. COMMITTED is workflow state, never a chain or certificate claim. */
const DRAFT_STATES: Record<string, StatusDescriptor> = {
  DRAFT: { icon: "·", label: "DRAFT", tone: "neutral", explanation: "An editable draft revision. Nothing is approved and nothing is published." },
  SUBMITTED: { icon: "→", label: "SUBMITTED", tone: "info", explanation: "Waiting for an independent approver. The creator and every editor of this draft are excluded from approval." },
  APPROVED: { icon: "✔", label: "APPROVED", tone: "info", explanation: "An independent approver bound this approval to the exact revision, payload hash and base version shown here." },
  REJECTED: { icon: "✖", label: "REJECTED", tone: "warn", explanation: "The approver rejected this revision. A new edit returns the draft to DRAFT." },
  COMMITTED: { icon: "✔", label: "COMMITTED", tone: "ok", explanation: "The workflow version is committed with its audit entry and outbox event. This is database workflow state, not a finalized Solana anchor, not a published certificate and not a claim that the record is current." },
};

const UNKNOWN_DRAFT_STATE: StatusDescriptor = {
  icon: "?",
  label: "UNKNOWN STATE",
  tone: "neutral",
  explanation: "The server returned a draft state this build does not describe, so no action is offered from it. Reload the draft or update the application.",
};

/** English explanations for the workflow error codes the backend answers with. */
const ERROR_SENTENCES: Record<string, string> = {
  SESSION_REQUIRED: "The admin session is missing or expired. Sign in again.",
  PERMISSION_FORBIDDEN: "The server denied this action for this session permissions or registry scope.",
  SELF_APPROVAL: "The server denies self-approval: the creator of a draft, and every editor of it, cannot approve it. A different approver must sign in.",
  REVISION_CONFLICT: "The draft revision changed on the server since this page loaded it. Reload the draft, review the new revision and retry explicitly; nothing was overwritten automatically.",
  APPROVAL_BINDING_MISMATCH: "The payload hash or base version no longer matches the revision this action would bind to. Reload the draft and review it again.",
  BASE_VERSION_CONFLICT: "The record committed version no longer matches the base version this attempt was opened against. Review the record state and start a new attempt.",
  IDEMPOTENCY_CONFLICT: "This idempotency key was already used for different content. Start a new attempt.",
  IDEMPOTENCY_KEY_REQUIRED: "Every workflow mutation needs an idempotency key; this client generates one per logical attempt.",
  ALREADY_COMMITTED: "This draft is already committed and cannot change.",
  INVALID_STATE: "The server state does not allow this action yet. Reload the draft to see its current state.",
  APPROVAL_REQUIRED: "Commit requires an independent approval of this exact revision first.",
  DRAFT_NOT_FOUND: "No draft with this UUID is visible to this session; absent and unauthorized drafts answer identically.",
  DRAFT_ID_INVALID: "Enter the draft UUID in 8-4-4-4-12 hexadecimal form.",
  DRAFT_RESPONSE_INVALID: "The server returned a draft shape this build cannot read, so nothing is displayed from it.",
  INVALID_PAYLOAD: "The payload must be a JSON object and the operation must be upsert or tombstone.",
  TOMBSTONE_PAYLOAD: "A tombstone carries an empty payload object: {}.",
  INVALID_JSON: "The payload field must contain a single JSON object.",
  INVALID_ID: "Record IDs allow letters, digits and . _ : - only, up to 128 characters.",
  INVALID_VERSION: "The base version must be a non-negative safe integer.",
  UNSUPPORTED_NUMBER: "Payload numbers must be safe integers; floats and out-of-range numbers are refused.",
  UNSUPPORTED_STRING: "Payload keys and values must be well-formed strings without U+0000.",
  RESERVED_FIELD_NAME: "A payload key uses a reserved name (__proto__) and is refused.",
  AMBIGUOUS_FIELD_PATH: "Payload keys must be non-empty, free of dots and unique after Unicode normalization.",
  PAYLOAD_TOO_LARGE: "The payload exceeds the workflow size limit.",
  UNSUPPORTED_NESTING: "The payload nests deeper than the workflow contract allows.",
  METHOD_NOT_ALLOWED: "The server does not allow this method on the workflow route.",
  UPSTREAM_UNAVAILABLE: "The admin API did not answer, so this page cannot confirm whether the action completed. Retry the same attempt unchanged; if this page is reloaded, the server keeps the pending attempt so it can be recovered from the list instead of repeated.",
  RESPONSE_NOT_JSON: "The response was unreadable, so this page cannot confirm whether the action completed. Retry the same attempt unchanged; if this page is reloaded, the server keeps the pending attempt so it can be recovered from the list instead of repeated.",
  REQUEST_FAILED: "The server refused the request.",
  ATTEMPT_RESPONSE_INVALID: "The server returned a pending-attempt shape this build cannot read, so nothing is displayed from it.",
  ATTEMPT_NOT_RECOVERABLE: "The server reports this attempt as completed but without one draft UUID this session can open; refresh the pending attempts and open the draft by its UUID instead.",
  ATTEMPT_ACK_FAILED: "The draft was read back with the same UUID, but the server did not acknowledge the attempt, so it stays listed as pending; refresh the pending attempts list to reconcile it.",
  ATTEMPT_CANCEL_FAILED: "The attempt was not cancelled, so it stays listed as pending; refresh the pending attempts list and cancel it again only if it is still prepared.",
  ATTEMPT_ALREADY_COMPLETED: "The server already completed this attempt, so it cannot be cancelled; refresh the pending attempts and open the draft it produced.",
  ATTEMPT_CANCELLED: "This attempt was cancelled on the server, so a late mutation under its key is permanently refused. Start a new attempt from the same input and review the draft state again.",
  ATTEMPT_UNCONFIRMED: "The server still counts this attempt as unconfirmed, so it cannot be acknowledged yet; the pending list keeps showing it until its outcome is read back.",
  ATTEMPT_NOT_FOUND: "The server no longer has this attempt for this session; refresh the pending attempts list to see what remains.",
  ATTEMPT_LIMIT_REACHED: "This session reached the server limit of outstanding attempts. Cancel prepared attempts or recover completed ones before starting another mutation.",
  INVALID_ATTEMPT: "The server refused the attempt envelope as malformed, so nothing was prepared and no mutation was sent.",
  DRAFT_LIST_RESPONSE_INVALID: "The server returned a draft list shape this build cannot read, so no drafts are displayed from it.",
  INVALID_CURSOR: "The draft list cursor was refused as malformed, so the list was not read; refresh the list to start again.",
  DRAFT_LIST_BUSY: "The server could not finish scanning readable drafts; refresh the draft list to try again.",
};

function describeError(code: string): string {
  if (!Object.hasOwn(ERROR_SENTENCES, code)) return "The server refused the request with an unlisted code.";
  return ERROR_SENTENCES[code];
}

/** The draft read model returned by GET /v2/admin/workflow/drafts/:uuid. */
interface DraftReadModel {
  draft_id: string;
  record_id: string;
  creator: string;
  revision: number;
  base_version: number;
  state: string;
  approver: string | null;
  committed_version: number | null;
  payload: Record<string, unknown>;
  payload_hash: string;
  operation: string;
}

/** Draft UUID shape accepted by the v2 workflow routes (mirrors the API client). */
const DRAFT_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The attempt actions of the durable workflow attempts contract. */
const ATTEMPT_ACTIONS: readonly string[] = ["create", "edit", "submit", "approve", "reject", "commit"];

/**
 * The outstanding-attempt DTO. It carries no payload and no credential, and an
 * attempt this build cannot read whole is refused rather than partly shown.
 */
function asAttempt(body: any): WorkflowAttempt | null {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return null;
  const { attemptId, idempotencyKey, state, draftId, action, recordId } = body;
  if (typeof attemptId !== "string" || !DRAFT_UUID.test(attemptId)) return null;
  if (typeof idempotencyKey !== "string" || !DRAFT_UUID.test(idempotencyKey) || idempotencyKey !== attemptId) return null;
  if (state !== "PREPARED" && state !== "COMPLETED") return null;
  if (draftId !== null && (typeof draftId !== "string" || !DRAFT_UUID.test(draftId))) return null;
  if (typeof action !== "string" || !ATTEMPT_ACTIONS.includes(action)) return null;
  if (typeof recordId !== "string" || recordId.length === 0) return null;
  return { attemptId, idempotencyKey, state, draftId, action: action as WorkflowAttempt["action"], recordId };
}

/** The whole list fails closed when any entry is unreadable. */
function asAttemptList(body: any): WorkflowAttempt[] | null {
  if (body === null || typeof body !== "object" || Array.isArray(body) || !Array.isArray(body.attempts)) return null;
  const attempts: WorkflowAttempt[] = [];
  for (const entry of body.attempts) {
    const attempt = asAttempt(entry);
    if (attempt === null) return null;
    attempts.push(attempt);
  }
  return attempts;
}

/** A draft this build cannot read is refused whole, never partly displayed. */
function asDraft(body: any): DraftReadModel | null {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return null;
  const { draft_id: draftId, record_id: recordId, creator, revision, base_version: baseVersion, state, payload, payload_hash: payloadHash, operation } = body;
  if (typeof draftId !== "string" || typeof recordId !== "string" || typeof creator !== "string") return null;
  if (!Number.isSafeInteger(revision) || !Number.isSafeInteger(baseVersion)) return null;
  if (typeof state !== "string" || typeof payloadHash !== "string" || typeof operation !== "string") return null;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) return null;
  return {
    draft_id: draftId,
    record_id: recordId,
    creator,
    revision,
    base_version: baseVersion,
    state,
    approver: typeof body.approver === "string" ? body.approver : null,
    committed_version: Number.isSafeInteger(body.committed_version) ? body.committed_version : null,
    payload: payload as Record<string, unknown>,
    payload_hash: payloadHash,
    operation,
  };
}

/** One draft list row of GET /v2/admin/workflow/drafts; it carries no payload. */
interface DraftListEntry {
  draft_id: string;
  record_id: string;
  creator: string;
  revision: number;
  base_version: number;
  state: string;
  approver: string | null;
  committed_version: number | null;
  payload_hash: string;
  operation: string;
}

/** A list row this build cannot read fails the whole page closed. */
function asDraftListEntry(body: any): DraftListEntry | null {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return null;
  const { draft_id: draftId, record_id: recordId, creator, revision, base_version: baseVersion, state, payload_hash: payloadHash, operation } = body;
  if (typeof draftId !== "string" || !DRAFT_UUID.test(draftId)) return null;
  if (typeof recordId !== "string" || typeof creator !== "string" || creator.length === 0) return null;
  if (!Number.isSafeInteger(revision) || !Number.isSafeInteger(baseVersion)) return null;
  if (typeof state !== "string" || typeof payloadHash !== "string" || typeof operation !== "string") return null;
  return {
    draft_id: draftId,
    record_id: recordId,
    creator,
    revision,
    base_version: baseVersion,
    state,
    approver: typeof body.approver === "string" ? body.approver : null,
    committed_version: Number.isSafeInteger(body.committed_version) ? body.committed_version : null,
    payload_hash: payloadHash,
    operation,
  };
}

/** The paged draft list: any unreadable row or cursor fails the page closed. */
function asDraftList(body: any): { drafts: DraftListEntry[]; nextCursor: string | null } | null {
  if (body === null || typeof body !== "object" || Array.isArray(body) || !Array.isArray(body.drafts)) return null;
  const nextCursor = body.nextCursor ?? null;
  if (nextCursor !== null && (typeof nextCursor !== "string" || !DRAFT_UUID.test(nextCursor))) return null;
  const drafts: DraftListEntry[] = [];
  for (const entry of body.drafts) {
    const model = asDraftListEntry(entry);
    if (model === null) return null;
    drafts.push(model);
  }
  return { drafts, nextCursor };
}

function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function parsePayload(text: string): { payload?: Record<string, unknown>; code?: string } {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { code: "INVALID_JSON" };
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return { code: "INVALID_JSON" };
  return { payload: value as Record<string, unknown> };
}

/**
 * RegistryWorkflow workspace: draft creation, UUID reads and the exact-revision
 * action chain (edit, submit, approve or reject, commit). Everything shown and
 * sent comes from the server session and the server draft; nothing here invents
 * a hash, revision, approval or privilege, and no credential is persisted.
 */
export function RegistryWorkflowPanel(): ReactNode {
  const { session } = useAdminSession();
  const canRead = hasPermission(session, "records.read");
  const canDraft = hasPermission(session, "records.draft");
  const canApprove = hasPermission(session, "records.approve");
  // A draft this session cannot read back must not be offered: the create and
  // workspace mutation controls need records.read as well as their own grant.
  const canMutateDrafts = canRead && canDraft;
  const canMutateApprovals = canRead && canApprove;
  const metadataPresent = session?.metadataPresent === true;

  const [recordId, setRecordId] = useState("");
  const [baseVersion, setBaseVersion] = useState("0");
  const [createOperation, setCreateOperation] = useState<"upsert" | "tombstone">("upsert");
  const [createPayload, setCreatePayload] = useState("{\n  \"parcelAddress\": \"1 Example Street, Yerevan\"\n}");

  const [draftIdInput, setDraftIdInput] = useState("");
  const [draft, setDraft] = useState<DraftReadModel | null>(null);
  const [committed, setCommitted] = useState<{ draftId: string; recordId: string; version: number; payloadHash: string } | null>(null);
  const [error, setError] = useState<{ code: string; sentence: string } | null>(null);
  const [stale, setStale] = useState(false);
  const [busy, setBusy] = useState(false);

  const [editOperation, setEditOperation] = useState<"upsert" | "tombstone">("upsert");
  const [editPayload, setEditPayload] = useState("{}");

  // Outstanding attempts come from the server and live in memory here only;
  // no payload, key or token is ever written to local or session storage. The
  // ref mirrors the list so asynchronous recovery reads the current set.
  const [attempts, setAttempts] = useState<WorkflowAttempt[] | null>(null);
  const [attemptsBusy, setAttemptsBusy] = useState(false);
  const [attemptsError, setAttemptsError] = useState<{ code: string; sentence: string } | null>(null);
  const attemptsRef = useRef<WorkflowAttempt[] | null>(null);
  // The draft list closes the manual-UUID gap: a session that may read drafts
  // can find a submitted draft, including a colleague's, and open it by row.
  // A server build without the route answers 404 and only this box says so.
  const [draftList, setDraftList] = useState<DraftListEntry[] | null>(null);
  const [draftListBusy, setDraftListBusy] = useState(false);
  const [draftListError, setDraftListError] = useState<{ code: string; sentence: string } | null>(null);
  const [draftListUnavailable, setDraftListUnavailable] = useState(false);
  const [draftListCursor, setDraftListCursor] = useState<string | null>(null);
  const storeAttempts = useCallback((next: WorkflowAttempt[] | null): void => {
    attemptsRef.current = next;
    setAttempts(next);
  }, []);
  const upsertAttempt = useCallback((attempt: WorkflowAttempt): void => {
    storeAttempts([...(attemptsRef.current ?? []).filter((entry) => entry.attemptId !== attempt.attemptId), attempt]);
  }, [storeAttempts]);
  const dropAttempt = useCallback((attemptId: string): void => {
    storeAttempts((attemptsRef.current ?? []).filter((entry) => entry.attemptId !== attemptId));
  }, [storeAttempts]);

  const fail = useCallback((cause: unknown): void => {
    if (cause instanceof ApiError) {
      setError({ code: cause.code, sentence: describeError(cause.code) });
      // A conflict means this view no longer matches the server; only the user
      // may reload and retry, so no automatic refresh or overwrite happens.
      if (cause.status === 409) setStale(true);
      return;
    }
    setError({ code: "REQUEST_FAILED", sentence: describeError("REQUEST_FAILED") });
  }, []);

  /**
   * Acknowledges exactly one attempt after its draft was read back with the
   * same UUID. A failed acknowledgment changes nothing locally: the attempt
   * stays durable on the server and keeps its row in this list.
   */
  const acknowledge = useCallback(async (attemptId: string): Promise<void> => {
    if (session === null) return;
    try {
      await workflowAcknowledgeAttempt(attemptId, { csrfToken: session.csrfToken });
      dropAttempt(attemptId);
    } catch (cause) {
      const code = cause instanceof ApiError ? cause.code : "ATTEMPT_ACK_FAILED";
      const sentence = Object.hasOwn(ERROR_SENTENCES, code) ? describeError(code) : describeError("ATTEMPT_ACK_FAILED");
      setError({ code, sentence });
    }
  }, [session, dropAttempt]);

  /** The startup and manual read of this session's outstanding attempts. */
  const refreshAttempts = useCallback(async (): Promise<void> => {
    setAttemptsBusy(true);
    setAttemptsError(null);
    try {
      const list = asAttemptList(await workflowListAttempts());
      if (list === null) {
        setAttemptsError({ code: "ATTEMPT_RESPONSE_INVALID", sentence: describeError("ATTEMPT_RESPONSE_INVALID") });
        return;
      }
      storeAttempts(list);
    } catch (cause) {
      setAttemptsError(cause instanceof ApiError
        ? { code: cause.code, sentence: describeError(cause.code) }
        : { code: "REQUEST_FAILED", sentence: describeError("REQUEST_FAILED") });
    } finally {
      setAttemptsBusy(false);
    }
  }, [storeAttempts]);

  /** One page of the read-only draft list; `after` continues from its cursor. */
  const loadDraftList = useCallback(async (after?: string): Promise<void> => {
    setDraftListBusy(true);
    setDraftListError(null);
    try {
      const page = asDraftList(await workflowListDrafts(after));
      if (page === null) {
        setDraftListError({ code: "DRAFT_LIST_RESPONSE_INVALID", sentence: describeError("DRAFT_LIST_RESPONSE_INVALID") });
        return;
      }
      setDraftListUnavailable(false);
      setDraftListCursor(page.nextCursor);
      setDraftList((current) => {
        // The first page replaces the list; later pages append without duplicates.
        if (after === undefined || current === null) return page.drafts;
        const seen = new Set(current.map((entry) => entry.draft_id));
        return [...current, ...page.drafts.filter((entry) => !seen.has(entry.draft_id))];
      });
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 404) {
        // A server build without the list route is not a workspace failure.
        setDraftList(null);
        setDraftListCursor(null);
        setDraftListUnavailable(true);
        return;
      }
      setDraftListError(cause instanceof ApiError
        ? { code: cause.code, sentence: describeError(cause.code) }
        : { code: "REQUEST_FAILED", sentence: describeError("REQUEST_FAILED") });
    } finally {
      setDraftListBusy(false);
    }
  }, []);

  /**
   * Cancels one prepared attempt only after an explicit click, and only then:
   * nothing here cancels silently, and a completed attempt is refused by the
   * server. The list is refreshed afterwards so it reflects the server again.
   */
  const cancelAttempt = useCallback(async (attemptId: string): Promise<void> => {
    if (session === null) return;
    setAttemptsBusy(true);
    setError(null);
    try {
      await workflowCancelAttempt(attemptId, { csrfToken: session.csrfToken });
    } catch (cause) {
      const code = cause instanceof ApiError ? cause.code : "ATTEMPT_CANCEL_FAILED";
      const sentence = Object.hasOwn(ERROR_SENTENCES, code) ? describeError(code) : describeError("ATTEMPT_CANCEL_FAILED");
      setError({ code, sentence });
    } finally {
      await refreshAttempts();
    }
  }, [session, refreshAttempts]);

  // Startup reads: once the session carries records.read, the durable pending
  // attempts and the readable draft list are loaded; both have manual refresh.
  useEffect(() => {
    if (session === null || !canRead) return;
    void refreshAttempts();
    void loadDraftList();
  }, [session, canRead, refreshAttempts, loadDraftList]);

  /**
   * Durable prepare of one logical mutation: the server hands out the
   * idempotency key for this exact path and body, stable until the attempt is
   * acknowledged. There is no locally generated fallback key, so a failed
   * prepare leaves no mutation to send.
   */
  const prepare = useCallback(async (
    path: string,
    body: Record<string, unknown>,
    expected: { action: string; recordId: string },
  ): Promise<WorkflowAttempt | null> => {
    if (session === null) return null;
    const attempt = asAttempt(await workflowPrepareAttempt({ path, body }, { csrfToken: session.csrfToken }));
    if (attempt === null || attempt.action !== expected.action || attempt.recordId !== expected.recordId) {
      setError({ code: "ATTEMPT_RESPONSE_INVALID", sentence: describeError("ATTEMPT_RESPONSE_INVALID") });
      return null;
    }
    upsertAttempt(attempt);
    return attempt;
  }, [session, upsertAttempt]);

  /** A read is trusted only when the same UUID comes back; anything else is refused whole. */
  const readDraft = useCallback(async (draftId: string): Promise<DraftReadModel | null> => {
    const model = asDraft(await workflowReadDraft(draftId));
    return model !== null && model.draft_id === draftId ? model : null;
  }, []);

  const showDraft = useCallback((model: DraftReadModel): void => {
    setDraft(model);
    setDraftIdInput(model.draft_id);
    setEditOperation(model.operation === "tombstone" ? "tombstone" : "upsert");
    setEditPayload(pretty(model.payload));
    setStale(false);
  }, []);

  /**
   * Opens the draft a completed attempt produced and acknowledges that attempt
   * only after the read came back with the same UUID. A failed read or a failed
   * acknowledgment leaves the attempt durable on the server.
   */
  const recover = useCallback(async (attemptId: string, draftId: string): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const model = await readDraft(draftId);
      if (model === null) {
        setDraft(null);
        setError({ code: "DRAFT_RESPONSE_INVALID", sentence: describeError("DRAFT_RESPONSE_INVALID") });
        return;
      }
      showDraft(model);
      await acknowledge(attemptId);
    } catch (cause) {
      fail(cause);
    } finally {
      setBusy(false);
    }
  }, [readDraft, showDraft, acknowledge, fail]);

  const loadDraft = useCallback(async (id: string): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const model = await readDraft(id);
      if (model === null) {
        setDraft(null);
        setError({ code: "DRAFT_RESPONSE_INVALID", sentence: describeError("DRAFT_RESPONSE_INVALID") });
        return;
      }
      showDraft(model);
      // A validated read acknowledges only the completed attempts bound to this
      // exact UUID. Prepared attempts, attempts of other drafts and attempts
      // whose acknowledgment failed all stay durable and outstanding.
      for (const attempt of [...(attemptsRef.current ?? [])]) {
        if (attempt.state !== "COMPLETED" || attempt.draftId !== model.draft_id) continue;
        await acknowledge(attempt.attemptId);
      }
    } catch (cause) {
      fail(cause);
    } finally {
      setBusy(false);
    }
  }, [readDraft, showDraft, acknowledge, fail]);

  const createDraft = useCallback(async (): Promise<void> => {
    if (session === null) return;
    const version = Number(baseVersion.trim());
    if (!/^\d+$/.test(baseVersion.trim()) || !Number.isSafeInteger(version)) {
      setError({ code: "INVALID_VERSION", sentence: describeError("INVALID_VERSION") });
      return;
    }
    const parsed = parsePayload(createPayload);
    if (parsed.payload === undefined) {
      const code = parsed.code ?? "INVALID_JSON";
      setError({ code, sentence: describeError(code) });
      return;
    }
    if (createOperation === "tombstone" && Object.keys(parsed.payload).length !== 0) {
      setError({ code: "TOMBSTONE_PAYLOAD", sentence: describeError("TOMBSTONE_PAYLOAD") });
      return;
    }
    const input = { recordId: recordId.trim(), baseVersion: version, operation: createOperation, payload: parsed.payload };
    setBusy(true);
    setError(null);
    try {
      // Prepare first: an unchanged retry gets the durable attempt's own key
      // back, while changed content becomes a different attempt.
      const attempt = await prepare(workflowCreatePath(), input, { action: "create", recordId: input.recordId });
      if (attempt === null) return;
      if (attempt.state === "COMPLETED") {
        // The server already applied this exact attempt: recover its draft
        // instead of repeating the mutation.
        if (attempt.draftId === null) {
          setError({ code: "ATTEMPT_NOT_RECOVERABLE", sentence: describeError("ATTEMPT_NOT_RECOVERABLE") });
          return;
        }
        setBusy(false);
        await recover(attempt.attemptId, attempt.draftId);
        return;
      }
      const response = await workflowCreateDraft(
        input,
        { csrfToken: session.csrfToken, idempotencyKey: attempt.idempotencyKey },
      );
      const createdId = typeof response?.draftId === "string" && DRAFT_UUID.test(response.draftId) ? response.draftId : null;
      if (createdId === null) {
        setError({ code: "DRAFT_RESPONSE_INVALID", sentence: describeError("DRAFT_RESPONSE_INVALID") });
        return;
      }
      setCommitted(null);
      setBusy(false);
      await recover(attempt.attemptId, createdId);
    } catch (cause) {
      fail(cause);
    } finally {
      setBusy(false);
    }
  }, [session, baseVersion, createPayload, createOperation, recordId, prepare, recover, fail]);

  const act = useCallback(async (action: WorkflowAction, body: Record<string, unknown>): Promise<void> => {
    if (session === null || draft === null) return;
    const draftId = draft.draft_id;
    setBusy(true);
    setError(null);
    try {
      // The attempt binds the exact action body: a changed revision, hash or
      // base version is a different attempt with its own key, while an
      // unchanged retry replays this one even if another draft was opened.
      const attempt = await prepare(workflowActionPath(draftId, action), body, { action, recordId: draft.record_id });
      if (attempt === null) return;
      if (attempt.state === "COMPLETED") {
        // This exact action already ran on the server; a validated read of its
        // own draft is the only recovery, and the mutation is not repeated.
        if (attempt.draftId === null) {
          setError({ code: "ATTEMPT_NOT_RECOVERABLE", sentence: describeError("ATTEMPT_NOT_RECOVERABLE") });
          return;
        }
        if (attempt.draftId !== draftId) {
          setError({ code: "ATTEMPT_RESPONSE_INVALID", sentence: describeError("ATTEMPT_RESPONSE_INVALID") });
          return;
        }
        setBusy(false);
        await recover(attempt.attemptId, draftId);
        return;
      }
      const response = await workflowAction(draftId, action, body, {
        csrfToken: session.csrfToken,
        idempotencyKey: attempt.idempotencyKey,
      });
      if (response?.committed !== undefined && response.committed !== null) {
        const receipt = response.committed;
        if (action !== "commit" || typeof receipt !== "object" || Array.isArray(receipt)
          || receipt.recordId !== draft.record_id || !Number.isSafeInteger(receipt.version)
          || receipt.version !== draft.base_version + 1 || receipt.payloadHash !== draft.payload_hash) {
          setError({ code: "DRAFT_RESPONSE_INVALID", sentence: describeError("DRAFT_RESPONSE_INVALID") });
          return;
        }
        setCommitted({ draftId, recordId: receipt.recordId, version: receipt.version, payloadHash: receipt.payloadHash });
      }
      setBusy(false);
      await recover(attempt.attemptId, draftId);
    } catch (cause) {
      fail(cause);
    } finally {
      setBusy(false);
    }
  }, [session, draft, prepare, recover, fail]);

  const exactBinding = (): Record<string, unknown> => ({
    expectedRevision: draft?.revision,
    payloadHash: draft?.payload_hash,
    baseVersion: draft?.base_version,
  });

  const saveEdit = useCallback(async (): Promise<void> => {
    if (draft === null) return;
    const parsed = parsePayload(editPayload);
    if (parsed.payload === undefined) {
      const code = parsed.code ?? "INVALID_JSON";
      setError({ code, sentence: describeError(code) });
      return;
    }
    if (editOperation === "tombstone" && Object.keys(parsed.payload).length !== 0) {
      setError({ code: "TOMBSTONE_PAYLOAD", sentence: describeError("TOMBSTONE_PAYLOAD") });
      return;
    }
    // The serialized body is the scope: changed bytes need a new idempotency
    // key, while a retry of the same edit replays the old one.
    await act("edit", { expectedRevision: draft.revision, operation: editOperation, payload: parsed.payload });
  }, [draft, editPayload, editOperation, act]);

  const state = draft === null ? null : Object.hasOwn(DRAFT_STATES, draft.state) ? DRAFT_STATES[draft.state] : UNKNOWN_DRAFT_STATE;
  const committedForDraft = committed !== null && draft !== null && committed.draftId === draft.draft_id && draft.state === "COMMITTED" && draft.committed_version === committed.version && draft.payload_hash === committed.payloadHash ? committed : null;
  const selfApproval = draft !== null && session !== null && draft.creator === session.username;
  const conflicts = stale;
  const granted = ["records.read", "records.draft", "records.approve"].filter((permission) => hasPermission(session, permission));

  return (
    <section className="ol-card" aria-labelledby="workflow-heading" data-testid="workflow-panel">
      <h1 id="workflow-heading">Registry workflow</h1>
      <p>
        Draft a registry record from its committed base version, submit it, have it approved by an
        independent person and commit it. Every action binds to the exact revision, payload hash and base
        version the server last returned, and a committed workflow version is not a chain publication.
        Every mutation is prepared as a durable attempt on the server first, so an interrupted attempt is
        recovered from the pending list instead of being repeated.
      </p>
      <dl className="ol-grid">
        <Field label="Signed in as" value={session?.username ?? "…"} />
        <Field
          label="Role"
          value={session === null ? "…" : roleLabel(session.role) === null ? session.role : roleLabel(session.role) + " (" + session.role + ")"}
        />
        <Field label="Deployment registry" value={session?.deploymentRegistryId ?? "not reported"} />
        <Field
          label="Workflow permissions from the session"
          value={<span data-testid="workflow-grants">{granted.length === 0 ? "none" : granted.join(", ")}</span>}
        />
      </dl>
      {metadataPresent ? null : (
        <p className="ol-error" data-testid="workflow-metadata-missing">
          The server session did not include permission metadata, so this page assumes no grants. Drafting,
          approval and commit stay unavailable until the session is refreshed; nothing is guessed from the
          role name.
        </p>
      )}
      {metadataPresent && !canRead ? (
        <p className="ol-error" data-testid="workflow-no-read">
          This session does not carry records.read for the deployment registry, so the workflow workspace
          stays read-only and the server refuses draft reads.
        </p>
      ) : null}

      <h2>Create a draft</h2>
      {canMutateDrafts ? (
        <form
          data-testid="workflow-create-form"
          onSubmit={(event) => { event.preventDefault(); void createDraft(); }}
        >
          <div className="ol-grid">
            <label className="ol-field">
              <span className="ol-label">Record ID</span>
              <input value={recordId} onChange={(event) => setRecordId(event.target.value)} data-testid="workflow-create-record" placeholder="SYNTHETIC-1" />
            </label>
            <label className="ol-field">
              <span className="ol-label">Base version</span>
              <input value={baseVersion} onChange={(event) => setBaseVersion(event.target.value)} data-testid="workflow-create-base-version" inputMode="numeric" />
            </label>
            <label className="ol-field">
              <span className="ol-label">Operation</span>
              <select
                value={createOperation}
                onChange={(event) => setCreateOperation(event.target.value === "tombstone" ? "tombstone" : "upsert")}
                data-testid="workflow-create-operation"
              >
                <option value="upsert">upsert</option>
                <option value="tombstone">tombstone</option>
              </select>
            </label>
          </div>
          <label className="ol-field">
            <span className="ol-label">Payload (JSON object; a tombstone requires {})</span>
            <textarea rows={6} value={createPayload} onChange={(event) => setCreatePayload(event.target.value)} data-testid="workflow-create-payload" />
          </label>
          <p>
            <button type="submit" data-variant="primary" disabled={busy} data-testid="workflow-create-submit">
              {busy ? "Sending…" : "Create draft"}
            </button>
          </p>
        </form>
      ) : (
        <p className="ol-muted" data-testid="workflow-create-unavailable">
          {canRead
            ? "Draft creation needs records.draft, which this session does not carry."
            : "Draft creation needs records.read in the deployment registry scope as well as records.draft; this session does not carry both."}
        </p>
      )}

      <h2>Open a draft</h2>
      <form
        data-testid="workflow-load-form"
        onSubmit={(event) => { event.preventDefault(); void loadDraft(draftIdInput.trim()); }}
      >
        <label className="ol-field">
          <span className="ol-label">Draft UUID</span>
          <input
            value={draftIdInput}
            onChange={(event) => setDraftIdInput(event.target.value)}
            data-testid="workflow-draft-id"
            placeholder="00000000-0000-0000-0000-000000000000"
            disabled={!canRead}
          />
        </label>
        <p>
          <button type="submit" disabled={busy || !canRead} data-testid="workflow-load-draft">Load draft</button>
        </p>
      </form>
      <p className="ol-muted">
        A draft can also be opened directly by the UUID the server returned when it was created, without
        using the list above.
      </p>

      {canRead ? (
        <section data-testid="workflow-draft-list-section">
          <h2>Draft list</h2>
          <p className="ol-muted">
            The newest drafts this session may read, including drafts created by other people, so an
            approver can find a submitted draft without its UUID. Opening a row only reads the draft, and
            this list never mutates anything.
          </p>
          <p>
            <button
              type="button"
              disabled={busy || draftListBusy}
              onClick={() => void loadDraftList()}
              data-testid="workflow-draft-list-refresh"
            >{draftListBusy ? "Reading…" : "Refresh draft list"}</button>{" "}
            {draftListCursor === null ? null : (
              <button
                type="button"
                disabled={busy || draftListBusy}
                onClick={() => void loadDraftList(draftListCursor)}
                data-testid="workflow-draft-list-next"
              >Load more drafts</button>
            )}
          </p>
          {draftListUnavailable ? (
            <p className="ol-muted" data-testid="workflow-draft-list-unavailable">
              This server build does not expose the draft list, so a draft is opened by its UUID below; the
              rest of the workspace is unaffected.
            </p>
          ) : draftListError !== null ? (
            <p className="ol-error" data-testid="workflow-draft-list-error">
              <code data-testid="workflow-draft-list-error-code">{draftListError.code}</code> — {draftListError.sentence}
            </p>
          ) : draftList === null ? (
            <p className="ol-muted" data-testid="workflow-draft-list-unread">
              The draft list has not been read yet; use the refresh button to read it.
            </p>
          ) : draftList.length === 0 ? (
            <p className="ol-muted" data-testid="workflow-draft-list-empty">No readable drafts.</p>
          ) : (
            <ul data-testid="workflow-draft-list">
              {draftList.map((entry) => (
                <li
                  key={entry.draft_id}
                  data-testid="workflow-draft-row"
                  data-draft-id={entry.draft_id}
                  data-state={entry.state}
                >
                  <code>{entry.record_id}</code> — revision {entry.revision} — {entry.state} — creator{" "}
                  <code>{entry.creator}</code>{" "}
                  <button
                    type="button"
                    disabled={busy || draftListBusy}
                    onClick={() => void loadDraft(entry.draft_id)}
                    data-testid="workflow-draft-open"
                  >Open</button>
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : null}

      {canRead ? (
        <section data-testid="workflow-attempts-section">
          <h2>Pending attempts</h2>
          <p className="ol-muted">
            Workflow mutations this session prepared on the server. A completed attempt can be opened from
            the draft it produced without repeating the mutation. A prepared attempt has no confirmed
            outcome: re-enter the original input and submit the same body to reuse it, or cancel it
            explicitly if it should never run. Nothing in this list is retried automatically, and a
            cancelled attempt stays cancelled.
          </p>
          <p>
            <button
              type="button"
              disabled={busy || attemptsBusy}
              onClick={() => void refreshAttempts()}
              data-testid="workflow-attempts-refresh"
            >{attemptsBusy ? "Refreshing…" : "Refresh pending attempts"}</button>
          </p>
          {attemptsError === null ? null : (
            <p className="ol-error" data-testid="workflow-attempts-error">
              <code data-testid="workflow-attempts-error-code">{attemptsError.code}</code> — {attemptsError.sentence}
            </p>
          )}
          {attempts === null ? (
            <p className="ol-muted" data-testid="workflow-attempts-unread">
              The pending attempts have not been read yet; use the refresh button to read them.
            </p>
          ) : attempts.length === 0 ? (
            <p className="ol-muted" data-testid="workflow-attempts-empty">No outstanding workflow attempts.</p>
          ) : (
            <ul data-testid="workflow-attempts-list">
              {attempts.map((attempt) => {
                const draftId = attempt.draftId;
                return (
                  <li
                    key={attempt.attemptId}
                    data-testid="workflow-attempt"
                    data-attempt-id={attempt.attemptId}
                    data-state={attempt.state}
                    data-action={attempt.action}
                    data-draft-id={draftId ?? ""}
                  >
                    <code>{attempt.action}</code> — <code>{attempt.recordId}</code> — {attempt.state}.{" "}
                    {attempt.state === "PREPARED" ? (
                      <>
                        <span data-testid="workflow-attempt-prepared">
                          No outcome is confirmed yet. Re-enter the original input and submit it again to
                          reuse this exact attempt; the mutation is never retried automatically.
                        </span>{" "}
                        <button
                          type="button"
                          disabled={busy || attemptsBusy}
                          onClick={() => void cancelAttempt(attempt.attemptId)}
                          data-testid="workflow-attempt-cancel"
                        >Cancel unconfirmed attempt</button>
                      </>
                    ) : draftId === null ? (
                      <span data-testid="workflow-attempt-no-draft">
                        The server reported no draft UUID for this completed attempt, so nothing is opened
                        from here; refresh the list or open the draft by its UUID.
                      </span>
                    ) : (
                      <button
                        type="button"
                        disabled={busy || attemptsBusy}
                        onClick={() => void recover(attempt.attemptId, draftId)}
                        data-testid="workflow-attempt-open"
                      >Open recovered draft</button>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      ) : null}

      {error !== null ? (
        <p className="ol-error" data-testid="workflow-error">
          <code data-testid="workflow-error-code">{error.code}</code> — {error.sentence}
        </p>
      ) : null}

      {draft === null || state === null ? null : (
        <div data-testid="workflow-draft" data-state={draft.state}>
          <h2>Draft</h2>
          <p>
            <StatusBadge status={state} testId="workflow-draft-state" />
          </p>
          <p className="ol-muted">{state.explanation}</p>
          {conflicts ? (
            <p className="ol-error" data-testid="workflow-stale-notice">
              This view no longer matches the server: the last action answered a conflict. Reload the draft
              and review the new revision before retrying; nothing was overwritten automatically.
            </p>
          ) : null}
          <dl className="ol-grid">
            <Field label="Draft ID" value={<code data-testid="workflow-draft-id-value">{draft.draft_id}</code>} />
            <Field label="Record" value={<span data-testid="workflow-draft-record">{draft.record_id}</span>} />
            <Field label="Operation" value={<span data-testid="workflow-draft-operation">{draft.operation}</span>} />
            <Field label="Revision" value={<span data-testid="workflow-draft-revision">{draft.revision}</span>} />
            <Field label="Base version" value={<span data-testid="workflow-draft-base-version">{draft.base_version}</span>} />
            <Field label="Payload hash" value={<code data-testid="workflow-draft-payload-hash">{draft.payload_hash}</code>} />
            <Field label="Creator" value={<span data-testid="workflow-draft-creator">{draft.creator}</span>} />
            <Field label="Approver" value={<span data-testid="workflow-draft-approver">{draft.approver ?? "—"}</span>} />
            <Field label="Committed version" value={<span data-testid="workflow-draft-committed-version">{draft.committed_version ?? "—"}</span>} />
          </dl>
          <h3>Payload</h3>
          <pre data-testid="workflow-draft-payload">{pretty(draft.payload)}</pre>
          {committedForDraft === null ? null : (
            <p className="ol-muted" data-testid="workflow-committed-note">
              Committed workflow version {committedForDraft.version} with payload hash
              <code data-testid="workflow-committed-hash">{committedForDraft.payloadHash}</code>. This is
              workflow database state: it is not a finalized Solana anchor, not a published certificate and
              not a claim that the record is current.
            </p>
          )}

          <h3>Edit</h3>
          {canMutateDrafts ? (
            <form onSubmit={(event) => { event.preventDefault(); void saveEdit(); }} data-testid="workflow-edit-form">
              <label className="ol-field">
                <span className="ol-label">Operation</span>
                <select
                  value={editOperation}
                  onChange={(event) => setEditOperation(event.target.value === "tombstone" ? "tombstone" : "upsert")}
                  data-testid="workflow-edit-operation"
                  disabled={draft.state === "COMMITTED" || conflicts}
                >
                  <option value="upsert">upsert</option>
                  <option value="tombstone">tombstone</option>
                </select>
              </label>
              <label className="ol-field">
                <span className="ol-label">Payload (JSON object)</span>
                <textarea
                  rows={6}
                  value={editPayload}
                  onChange={(event) => setEditPayload(event.target.value)}
                  data-testid="workflow-edit-payload"
                  disabled={draft.state === "COMMITTED" || conflicts}
                />
              </label>
              <p>
                <button
                  type="submit"
                  disabled={busy || draft.state === "COMMITTED" || conflicts}
                  data-testid="workflow-edit-save"
                >Save new revision</button>
              </p>
            </form>
          ) : (
            <p className="ol-muted" data-testid="workflow-edit-unavailable">
              {canRead
                ? "Editing needs records.draft."
                : "Editing needs records.read in the deployment registry scope as well as records.draft."}
            </p>
          )}

          <h3>Actions</h3>
          <p className="ol-muted" data-testid="workflow-actions">
            Every action sends this draft exact revision {draft.revision}, payload hash and base version{" "}
            {draft.base_version}.
          </p>
          {selfApproval ? (
            <p className="ol-muted" data-testid="workflow-self-approval-notice">
              You created this draft, so the server will deny an approval from this account.
            </p>
          ) : null}
          <p>
            <button
              type="button"
              disabled={busy || !canMutateDrafts || draft.state !== "DRAFT" || conflicts}
              onClick={() => void act("submit", exactBinding())}
              data-testid="workflow-submit"
            >Submit for approval</button>{" "}
            <button
              type="button"
              disabled={busy || !canMutateApprovals || draft.state !== "SUBMITTED" || conflicts}
              onClick={() => void act("approve", exactBinding())}
              data-testid="workflow-approve"
            >Approve revision {draft.revision}</button>{" "}
            <button
              type="button"
              disabled={busy || !canMutateApprovals || draft.state !== "SUBMITTED" || conflicts}
              onClick={() => void act("reject", exactBinding())}
              data-testid="workflow-reject"
            >Reject revision {draft.revision}</button>{" "}
            <button
              type="button"
              disabled={busy || !canMutateDrafts || draft.state !== "APPROVED" || conflicts}
              onClick={() => void act("commit", exactBinding())}
              data-testid="workflow-commit"
            >Commit approved revision</button>{" "}
            <button
              type="button"
              disabled={busy || !canRead}
              onClick={() => void loadDraft(draft.draft_id)}
              data-testid="workflow-reload"
            >Reload draft</button>
          </p>
        </div>
      )}
    </section>
  );
}
