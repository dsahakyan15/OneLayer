"use client";

// Browser-side access to the same-origin proxies. The CSRF token lives in
// component state for the lifetime of the page; the session itself is an
// HttpOnly cookie the browser never reads.

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message?: string) {
    super(message ?? code);
    this.status = status;
    this.code = code;
  }
}

// The v2 admin surface answers workflow errors as `{ error: CODE }`, while the
// legacy admin routes answer `{ code: CODE }`; both become ApiError.code.
function errorCode(body: any): string {
  if (typeof body?.code === "string" && body.code.length > 0) return body.code;
  if (typeof body?.error === "string" && body.error.length > 0) return body.error;
  return "REQUEST_FAILED";
}

async function parse(response: Response): Promise<any> {
  if (response.status === 204) return null;
  const text = await response.text();
  let body: any = null;
  try {
    body = text.length === 0 ? null : JSON.parse(text);
  } catch {
    throw new ApiError(response.status, "RESPONSE_NOT_JSON", text.slice(0, 200));
  }
  if (!response.ok) throw new ApiError(response.status, errorCode(body), body?.message);
  return body;
}

export interface AdminRequestOptions {
  method?: string;
  body?: unknown;
  csrfToken?: string;
  idempotencyKey?: string;
}

export async function admin(path: string, options: AdminRequestOptions = {}): Promise<any> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.csrfToken !== undefined) headers["x-onelayer-csrf"] = options.csrfToken;
  if (options.idempotencyKey !== undefined) headers["idempotency-key"] = options.idempotencyKey;
  return parse(await fetch(`/api/admin${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    cache: "no-store",
  }));
}

export async function publicApi(path: string): Promise<any> {
  return parse(await fetch(`/api/public${path}`, { cache: "no-store" }));
}

/**
 * A 422 carrying an INVALID verdict is a verification result, not a transport
 * failure; anything else non-2xx stays an error.
 */
async function parseVerification(response: Response): Promise<any> {
  const text = await response.text();
  let body: any = null;
  try {
    body = text.length === 0 ? null : JSON.parse(text);
  } catch {
    throw new ApiError(response.status, "RESPONSE_NOT_JSON", text.slice(0, 200));
  }
  if (!response.ok && !(response.status === 422 && body?.status === "INVALID")) {
    throw new ApiError(response.status, errorCode(body), body?.message);
  }
  return body;
}

export interface VerifyOutcome {
  /**
   * Envelope to render: `v2` is the current envelope, and `discarded` is an
   * answer whose wire version this build cannot interpret — including an empty or
   * missing body — which the result view renders fail-closed without repeating any
   * claim from the answer.
   */
  protocol: "v2" | "discarded";
  body: any;
}

/**
 * A v2 envelope is an object carrying `resultVersion: 2`. Anything else is not an
 * answer this build understands: `parse` answers an empty 200 body with null, and
 * that case must reach the result view as `discarded` instead of being read.
 */
function isV2Envelope(body: unknown): body is Record<string, unknown> {
  return typeof body === "object" && body !== null && !Array.isArray(body)
    && (body as { resultVersion?: unknown }).resultVersion === 2;
}

/**
 * Certificate verification against the verifier's `/v2/verify` envelope. Only
 * `resultVersion: 2` is read with v2 assumptions; any other version is handed to
 * the result view, which discards it. V2 is the only route this client calls: an
 * unavailable or failing verifier stays an error. The legacy `/v1/verify` route
 * exists for compatibility, never as an automatic fallback.
 */
export async function verify(certificatePackage: string): Promise<VerifyOutcome> {
  const body = await parseVerification(await fetch("/api/verify/v2/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ certificatePackage, requiredCommitment: "finalized" }),
    cache: "no-store",
  }));
  return isV2Envelope(body) ? { protocol: "v2", body } : { protocol: "discarded", body };
}

const WORKFLOW_UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const WORKFLOW_DRAFT_ID = new RegExp(`^${WORKFLOW_UUID}$`);
export const WORKFLOW_ACTIONS = ["edit", "submit", "approve", "reject", "commit"] as const;
export type WorkflowAction = (typeof WORKFLOW_ACTIONS)[number];

/** The mutation actions of the durable attempts contract, `create` included. */
export type WorkflowAttemptAction = "create" | WorkflowAction;
export type WorkflowAttemptState = "PREPARED" | "COMPLETED";

/** The outstanding-attempt DTO: it carries no payload and no session token. */
export interface WorkflowAttempt {
  attemptId: string;
  idempotencyKey: string;
  state: WorkflowAttemptState;
  draftId: string | null;
  action: WorkflowAttemptAction;
  recordId: string;
}

/** The exact v2 admin mutation paths the attempts contract may prepare. */
const WORKFLOW_ATTEMPT_PATH = new RegExp(
  `^/v2/admin/workflow/drafts(?:/${WORKFLOW_UUID}/(?:edit|submit|approve|reject|commit))?$`,
);

export interface WorkflowMutationOptions {
  csrfToken: string;
  /**
   * The key the server prepared for this exact logical attempt. There is no
   * locally generated fallback: a failed prepare sends no mutation at all.
   */
  idempotencyKey: string;
}

export interface WorkflowDraftInput {
  recordId: string;
  baseVersion: number;
  operation: "upsert" | "tombstone";
  payload: Record<string, unknown>;
}

/**
 * The registry-workflow surface exposes only the exact routes below, so a caller
 * cannot reach another v2 admin command through this helper.
 */
async function workflowRequest(
  path: string,
  options: { method: "GET" | "POST"; body?: unknown } & Partial<WorkflowMutationOptions>,
): Promise<any> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.csrfToken !== undefined) headers["x-onelayer-csrf"] = options.csrfToken;
  if (options.idempotencyKey !== undefined) headers["idempotency-key"] = options.idempotencyKey;
  return parse(await fetch(`/v2/admin${path}`, {
    method: options.method,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    cache: "no-store",
  }));
}

/** `POST /v2/admin/workflow/drafts` → `{ draftId, revision, payloadHash, baseVersion, state }`. */
export async function workflowCreateDraft(input: WorkflowDraftInput, options: WorkflowMutationOptions): Promise<any> {
  return workflowRequest("/workflow/drafts", { method: "POST", body: input, ...options });
}

/** `GET /v2/admin/workflow/drafts/:uuid` — the draft read model, keyed by UUID. */
export async function workflowReadDraft(draftId: string): Promise<any> {
  if (!WORKFLOW_DRAFT_ID.test(draftId)) throw new ApiError(0, "DRAFT_ID_INVALID", draftId);
  return workflowRequest(`/workflow/drafts/${draftId}`, { method: "GET" });
}

/**
 * `GET /v2/admin/workflow/drafts?after=<uuid>` → `{ drafts, nextCursor }`: one
 * page of at most 50 drafts this session may read, including drafts created by
 * other people, so an approver can find a submitted draft without its UUID.
 * A server build without this route answers 404; the workspace keeps working.
 */
export async function workflowListDrafts(after?: string): Promise<any> {
  if (after !== undefined && !WORKFLOW_DRAFT_ID.test(after)) {
    throw new ApiError(0, "WORKFLOW_PATH_NOT_ALLOWED", after);
  }
  return workflowRequest(`/workflow/drafts${after === undefined ? "" : `?after=${after}`}`, { method: "GET" });
}

/** The exact create path the attempts contract prepares. */
export function workflowCreatePath(): string {
  return "/v2/admin/workflow/drafts";
}

/** The exact action path of one draft; a foreign UUID or action is refused here. */
export function workflowActionPath(draftId: string, action: WorkflowAction): string {
  if (!WORKFLOW_DRAFT_ID.test(draftId) || !WORKFLOW_ACTIONS.includes(action)) {
    throw new ApiError(0, "WORKFLOW_PATH_NOT_ALLOWED", `${draftId}/${action}`);
  }
  return `/v2/admin/workflow/drafts/${draftId}/${action}`;
}

/**
 * `POST /v2/admin/workflow/drafts/:uuid/edit|submit|approve|reject|commit`.
 * Every action carries the exact revision, payload hash and base version the
 * server last returned; the UI never invents either value.
 */
export async function workflowAction(
  draftId: string,
  action: WorkflowAction,
  body: Record<string, unknown>,
  options: WorkflowMutationOptions,
): Promise<any> {
  return workflowRequest(`/workflow/drafts/${draftId}/${action}`, { method: "POST", body, ...options });
}

/**
 * `POST /v2/admin/workflow/attempts` — durably prepare one logical mutation
 * before it is sent, bound to the actor and registry of this session. The
 * answer carries the idempotency key the mutation must use; the server keeps it
 * stable for the same canonical path and body until the attempt is
 * acknowledged. Nothing local can substitute for it: no unsafe fallback exists.
 */
export async function workflowPrepareAttempt(
  request: { path: string; body: Record<string, unknown> },
  options: { csrfToken: string },
): Promise<any> {
  if (!WORKFLOW_ATTEMPT_PATH.test(request.path)
    || request.body === null || typeof request.body !== "object" || Array.isArray(request.body)) {
    throw new ApiError(0, "WORKFLOW_PATH_NOT_ALLOWED", request.path);
  }
  return workflowRequest("/workflow/attempts", {
    method: "POST",
    body: { path: request.path, body: request.body },
    csrfToken: options.csrfToken,
  });
}

/**
 * `GET /v2/admin/workflow/attempts` → `{ attempts: WorkflowAttempt[] }`: this
 * session's outstanding attempts, without payloads or credentials.
 */
export async function workflowListAttempts(): Promise<any> {
  return workflowRequest("/workflow/attempts", { method: "GET" });
}

/**
 * `POST /v2/admin/workflow/attempts/:uuid/ack` → `{ acknowledged: true }` for a
 * completed attempt of this session. Callers acknowledge only after a validated
 * read of the same draft UUID came back; a failed acknowledgment leaves the
 * attempt durable on the server.
 */
export async function workflowAcknowledgeAttempt(attemptId: string, options: { csrfToken: string }): Promise<any> {
  if (!WORKFLOW_DRAFT_ID.test(attemptId)) throw new ApiError(0, "WORKFLOW_PATH_NOT_ALLOWED", attemptId);
  return workflowRequest(`/workflow/attempts/${attemptId}/ack`, { method: "POST", body: {}, csrfToken: options.csrfToken });
}

/**
 * `POST /v2/admin/workflow/attempts/:uuid/cancel` → `{ cancelled: true }` for a
 * prepared attempt of this session. Cancellation is explicit and final: the
 * server permanently refuses a late mutation under the cancelled key, and a
 * cancelled attempt never returns in the outstanding list.
 */
export async function workflowCancelAttempt(attemptId: string, options: { csrfToken: string }): Promise<any> {
  if (!WORKFLOW_DRAFT_ID.test(attemptId)) throw new ApiError(0, "WORKFLOW_PATH_NOT_ALLOWED", attemptId);
  return workflowRequest(`/workflow/attempts/${attemptId}/cancel`, { method: "POST", body: {}, csrfToken: options.csrfToken });
}
