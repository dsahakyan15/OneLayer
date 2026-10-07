import { expect, test, type Page } from "@playwright/test";

const FIXTURE = `http://127.0.0.1:${process.env.ONELAYER_E2E_FIXTURE_PORT ?? "8199"}`;

const WORKER = { username: "registry_worker", password: "registry-worker-password-0123456789" };
const APPROVER = { username: "registry_approver", password: "registry-approver-password-0123456789" };
const AUDITOR = { username: "auditor", password: "auditor-password-0123456789" };
const UPSERT_PAYLOAD = '{\n  "parcelAddress": "1 Example Street, Yerevan",\n  "areaSquareMeters": 120\n}';

async function scenario(page: Page, body: Record<string, unknown>): Promise<void> {
  expect((await page.request.post(`${FIXTURE}/__fixture/scenario`, { data: body })).ok()).toBeTruthy();
}

async function signIn(page: Page, account: { username: string; password: string }): Promise<void> {
  await page.goto("/admin");
  await page.getByTestId("login-username").fill(account.username);
  await page.getByTestId("login-password").fill(account.password);
  await page.getByTestId("login-submit").click();
  await expect(page.getByTestId("session-username")).toHaveText(account.username);
}

async function signOut(page: Page): Promise<void> {
  await page.getByTestId("logout").click();
  await expect(page.getByTestId("login-username")).toBeVisible();
}

/** Creates an upsert draft through the workspace and returns its server UUID. */
async function createDraft(page: Page, recordId: string, payload = UPSERT_PAYLOAD): Promise<string> {
  await page.goto("/admin/workflow");
  await page.getByTestId("workflow-create-record").fill(recordId);
  await page.getByTestId("workflow-create-base-version").fill("0");
  await page.getByTestId("workflow-create-payload").fill(payload);
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("DRAFT");
  return await page.getByTestId("workflow-draft-id-value").innerText();
}

async function loadDraft(page: Page, draftId: string): Promise<void> {
  await page.goto("/admin/workflow");
  await page.getByTestId("workflow-draft-id").fill(draftId);
  await page.getByTestId("workflow-load-draft").click();
  await expect(page.getByTestId("workflow-draft-id-value")).toHaveText(draftId);
}

test("a writer drafts, refuses a malformed tombstone and submits for approval", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  await signIn(page, WORKER);
  await page.goto("/admin/workflow");
  await expect(page.getByTestId("workflow-grants")).toContainText("records.draft");
  // A workflow state is never labelled as a publication or a current record.
  await expect(page.getByTestId("workflow-panel")).not.toContainText("CURRENT");
  await expect(page.getByTestId("workflow-panel")).not.toContainText("PUBLISHED");

  await page.getByTestId("workflow-create-record").fill("SYNTHETIC-W1");
  await page.getByTestId("workflow-create-operation").selectOption("tombstone");
  await page.getByTestId("workflow-create-payload").fill(UPSERT_PAYLOAD);
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-error-code")).toHaveText("TOMBSTONE_PAYLOAD");

  await page.getByTestId("workflow-create-operation").selectOption("upsert");
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("DRAFT");
  await expect(page.getByTestId("workflow-draft-revision")).toHaveText("1");
  await expect(page.getByTestId("workflow-draft-payload-hash")).toHaveText(/^[0-9a-f]{64}$/);
  await expect(page.getByTestId("workflow-draft-creator")).toHaveText("registry_worker");

  // No cookie, CSRF token or idempotency key is ever persisted by the browser.
  expect(await page.evaluate(() => window.localStorage.length + window.sessionStorage.length)).toBe(0);

  // The writer does not carry records.approve, so that control stays unavailable.
  await expect(page.getByTestId("workflow-approve")).toBeDisabled();
  await page.getByTestId("workflow-submit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("SUBMITTED");
  await expect(page.getByTestId("workflow-commit")).toBeDisabled();
});

test("a tombstone draft keeps an empty payload", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  await signIn(page, WORKER);
  await page.goto("/admin/workflow");
  await page.getByTestId("workflow-create-record").fill("SYNTHETIC-W2");
  await page.getByTestId("workflow-create-operation").selectOption("tombstone");
  await page.getByTestId("workflow-create-payload").fill("{}");
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-draft-record")).toHaveText("SYNTHETIC-W2");
  await expect(page.getByTestId("workflow-draft-operation")).toHaveText("tombstone");
  await expect(page.getByTestId("workflow-draft-payload")).toHaveText("{}");
});

test("an independent approver approves the exact revision and the writer commits it", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  await signIn(page, WORKER);
  const draftId = await createDraft(page, "SYNTHETIC-W3");
  await page.getByTestId("workflow-submit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("SUBMITTED");
  const hash = await page.getByTestId("workflow-draft-payload-hash").innerText();

  await signOut(page);
  await signIn(page, APPROVER);
  await loadDraft(page, draftId);
  await expect(page.getByTestId("workflow-draft-payload-hash")).toHaveText(hash);
  await expect(page.getByTestId("workflow-draft-approver")).toHaveText("—");
  await expect(page.getByTestId("workflow-submit")).toBeDisabled();
  await expect(page.getByTestId("workflow-approve")).toBeEnabled();
  await page.getByTestId("workflow-approve").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("APPROVED");
  await expect(page.getByTestId("workflow-draft-approver")).toHaveText("registry_approver");

  await signOut(page);
  await signIn(page, WORKER);
  await loadDraft(page, draftId);
  await expect(page.getByTestId("workflow-draft-state")).toContainText("APPROVED");
  await page.getByTestId("workflow-commit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("COMMITTED");
  await expect(page.getByTestId("workflow-draft-committed-version")).toHaveText("1");
  await expect(page.getByTestId("workflow-committed-note")).toContainText("not a finalized Solana anchor");
  await expect(page.getByTestId("workflow-panel")).not.toContainText("CURRENT");
  await expect(page.getByTestId("workflow-panel")).not.toContainText("PUBLISHED");
});

test("the server denies self-approval and no approval is fabricated", async ({ page }) => {
  await scenario(page, { resetWorkflow: true, workflowSelfApprovalActor: true });
  await signIn(page, WORKER);
  const draftId = await createDraft(page, "SYNTHETIC-W4");
  await page.getByTestId("workflow-submit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("SUBMITTED");
  await expect(page.getByTestId("workflow-self-approval-notice")).toBeVisible();
  await page.getByTestId("workflow-approve").click();
  await expect(page.getByTestId("workflow-error-code")).toHaveText("SELF_APPROVAL");
  await expect(page.getByTestId("workflow-error")).toContainText("denies self-approval");
  // The view keeps reflecting the server state instead of a local approval.
  await expect(page.getByTestId("workflow-draft-state")).toContainText("SUBMITTED");
  await expect(page.getByTestId("workflow-draft-approver")).toHaveText("—");
  await loadDraft(page, draftId);
  await expect(page.getByTestId("workflow-draft-state")).toContainText("SUBMITTED");
});

test("a stale revision conflicts and only an explicit reload moves the view", async ({ browser }) => {
  const workerContext = await browser.newContext();
  const approverContext = await browser.newContext();
  const worker = await workerContext.newPage();
  const approver = await approverContext.newPage();
  try {
    await scenario(worker, { resetWorkflow: true });
    await signIn(worker, WORKER);
    const draftId = await createDraft(worker, "SYNTHETIC-W5");
    await worker.getByTestId("workflow-submit").click();
    await expect(worker.getByTestId("workflow-draft-state")).toContainText("SUBMITTED");

    await signIn(approver, APPROVER);
    await loadDraft(approver, draftId);
    await expect(approver.getByTestId("workflow-draft-revision")).toHaveText("1");

    // The writer edits the draft, so the approver view becomes stale.
    await loadDraft(worker, draftId);
    await worker.getByTestId("workflow-edit-payload").fill('{\n  "parcelAddress": "2 Example Street, Yerevan"\n}');
    await worker.getByTestId("workflow-edit-save").click();
    await expect(worker.getByTestId("workflow-draft-revision")).toHaveText("2");

    await approver.getByTestId("workflow-approve").click();
    await expect(approver.getByTestId("workflow-error-code")).toHaveText("REVISION_CONFLICT");
    await expect(approver.getByTestId("workflow-stale-notice")).toBeVisible();
    // Nothing is refreshed or overwritten until the user asks for it.
    await expect(approver.getByTestId("workflow-draft-revision")).toHaveText("1");
    await expect(approver.getByTestId("workflow-approve")).toBeDisabled();

    await approver.getByTestId("workflow-reload").click();
    await expect(approver.getByTestId("workflow-draft-revision")).toHaveText("2");
    await expect(approver.getByTestId("workflow-draft-state")).toContainText("DRAFT");
    await expect(approver.getByTestId("workflow-stale-notice")).toHaveCount(0);
  } finally {
    await workerContext.close();
    await approverContext.close();
  }
});

test("a retried attempt reuses its idempotency key and changed content needs a new one", async ({ page }) => {
  await scenario(page, { resetWorkflow: true, workflowUnavailableOnce: true });
  const keys: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().includes("/v2/admin/workflow/drafts")) {
      keys.push(request.headers()["idempotency-key"] ?? "");
    }
  });
  await signIn(page, WORKER);
  await page.goto("/admin/workflow");
  await page.getByTestId("workflow-create-record").fill("SYNTHETIC-W6");
  await page.getByTestId("workflow-create-payload").fill(UPSERT_PAYLOAD);
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-error-code")).toHaveText("UPSTREAM_UNAVAILABLE");

  // The same attempt, retried unchanged, keeps its key and creates one draft.
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("DRAFT");
  const draftId = await page.getByTestId("workflow-draft-id-value").innerText();
  expect(keys).toHaveLength(2);
  expect(keys[1]).toBe(keys[0]);

  // A failed edit retried unchanged keeps one key; different bytes need a new one.
  await scenario(page, { workflowUnavailableOnce: true });
  await page.getByTestId("workflow-edit-payload").fill('{\n  "parcelAddress": "Edited once"\n}');
  await page.getByTestId("workflow-edit-save").click();
  await expect(page.getByTestId("workflow-error-code")).toHaveText("UPSTREAM_UNAVAILABLE");
  await page.getByTestId("workflow-edit-save").click();
  await expect(page.getByTestId("workflow-draft-revision")).toHaveText("2");
  await page.getByTestId("workflow-edit-payload").fill('{\n  "parcelAddress": "Edited twice"\n}');
  await page.getByTestId("workflow-edit-save").click();
  await expect(page.getByTestId("workflow-draft-revision")).toHaveText("3");
  expect(keys).toHaveLength(5);
  expect(keys[3]).toBe(keys[2]);
  expect(keys[4]).not.toBe(keys[2]);
  expect(keys[2]).not.toBe(keys[0]);

  // Exactly one draft exists: reopening the returned UUID shows the same draft.
  await loadDraft(page, draftId);
  await expect(page.getByTestId("workflow-draft-id-value")).toHaveText(draftId);
  await expect(page.getByTestId("workflow-draft-revision")).toHaveText("3");
});

test("a read-only actor sees the draft but no mutation controls", async ({ browser }) => {
  const workerContext = await browser.newContext();
  const auditorContext = await browser.newContext();
  const worker = await workerContext.newPage();
  const auditor = await auditorContext.newPage();
  try {
    await scenario(worker, { resetWorkflow: true });
    await signIn(worker, WORKER);
    const draftId = await createDraft(worker, "SYNTHETIC-W7");
    await worker.getByTestId("workflow-submit").click();
    await expect(worker.getByTestId("workflow-draft-state")).toContainText("SUBMITTED");

    await signIn(auditor, AUDITOR);
    await expect(auditor.getByTestId("nav-workflow")).toBeVisible();
    await loadDraft(auditor, draftId);
    await expect(auditor.getByTestId("workflow-draft-state")).toContainText("SUBMITTED");
    await expect(auditor.getByTestId("workflow-create-unavailable")).toBeVisible();
    await expect(auditor.getByTestId("workflow-edit-unavailable")).toBeVisible();
    await expect(auditor.getByTestId("workflow-submit")).toBeDisabled();
    await expect(auditor.getByTestId("workflow-approve")).toBeDisabled();
    await expect(auditor.getByTestId("workflow-reject")).toBeDisabled();
    await expect(auditor.getByTestId("workflow-commit")).toBeDisabled();
  } finally {
    await workerContext.close();
    await auditorContext.close();
  }
});

test("a session without permission metadata stays read-only and guesses no grants", async ({ page }) => {
  await scenario(page, { resetWorkflow: true, sessionMetadataOmitted: true });
  await signIn(page, WORKER);
  await expect(page.getByTestId("nav-workflow")).toHaveCount(0);
  await page.goto("/admin/workflow");
  await expect(page.getByTestId("workflow-metadata-missing")).toBeVisible();
  await expect(page.getByTestId("workflow-grants")).toHaveText("none");
  await expect(page.getByTestId("workflow-create-form")).toHaveCount(0);
  await expect(page.getByTestId("workflow-load-draft")).toBeDisabled();
});

test("a session scoped to a foreign registry stays hidden and read-only", async ({ page }) => {
  await scenario(page, { resetWorkflow: true, sessionForeignRegistry: true });
  await signIn(page, WORKER);
  // Permissions alone are not a grant: the deployment registry must be in scope.
  await expect(page.getByTestId("nav-workflow")).toHaveCount(0);
  await page.goto("/admin/workflow");
  await expect(page.getByTestId("workflow-no-read")).toBeVisible();
  await expect(page.getByTestId("workflow-grants")).toHaveText("none");
  await expect(page.getByTestId("workflow-create-form")).toHaveCount(0);
  await expect(page.getByTestId("workflow-load-draft")).toBeDisabled();
  // The server refuses the same session, so the UI is not the only control.
  const denied = await page.evaluate(async () => {
    const response = await fetch("/v2/admin/workflow/drafts/00000000-0000-0000-0000-000000000000", { cache: "no-store" });
    return { status: response.status, body: await response.json().catch(() => null) as { error?: string } | null };
  });
  expect(denied.status).toBe(403);
  expect(denied.body?.error).toBe("PERMISSION_FORBIDDEN");
});


test("changed draft creation after an uncertain failure starts a new idempotent attempt", async ({ page }) => {
  await scenario(page, { resetWorkflow: true, workflowUnavailableOnce: true });
  const keys: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/v2/admin/workflow/drafts")) {
      keys.push(request.headers()["idempotency-key"] ?? "");
    }
  });
  await signIn(page, WORKER);
  await page.goto("/admin/workflow");
  await page.getByTestId("workflow-create-record").fill("SYNTHETIC-W8");
  await page.getByTestId("workflow-create-payload").fill(UPSERT_PAYLOAD);
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-error-code")).toHaveText("UPSTREAM_UNAVAILABLE");

  // The first request may have landed despite the unavailable response. A new
  // payload is a different logical attempt, never a replay under its old key.
  await page.getByTestId("workflow-create-payload").fill('{"parcelAddress":"Changed after failure"}');
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("DRAFT");
  await expect(page.getByTestId("workflow-draft-payload")).toContainText("Changed after failure");
  expect(keys).toHaveLength(2);
  expect(keys[0]).not.toBe("");
  expect(keys[1]).not.toBe(keys[0]);
});

test("an unavailable draft read after a mutation recovers the same draft without repeating the mutation", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  await signIn(page, WORKER);
  await page.goto("/admin/workflow");
  let refuseRead = true;
  await page.route("**/v2/admin/workflow/drafts/*", async route => {
    if (route.request().method() === "GET" && refuseRead) {
      refuseRead = false;
      await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "UPSTREAM_UNAVAILABLE" }) });
    } else await route.continue();
  });
  const creates: string[] = [];
  const edits: string[] = [];
  page.on("request", (request) => {
    if (request.method() !== "POST") return;
    if (request.url().endsWith("/v2/admin/workflow/drafts")) creates.push(request.url());
    if (request.url().endsWith("/edit")) edits.push(request.url());
  });
  await page.getByTestId("workflow-create-record").fill("SYNTHETIC-W9");
  await page.getByTestId("workflow-create-payload").fill(UPSERT_PAYLOAD);
  const created = () => page.waitForResponse(response => response.request().method() === "POST"
    && response.url().endsWith("/v2/admin/workflow/drafts"));
  const [first] = await Promise.all([created(), page.getByTestId("workflow-create-submit").click()]);
  const firstBody = await first.json();
  expect(first.status()).toBe(201);
  await expect(page.getByTestId("workflow-error-code")).toHaveText("UPSTREAM_UNAVAILABLE");
  expect(creates).toHaveLength(1);

  // The retry finds the durable completed attempt and reads its draft instead
  // of repeating the create.
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-draft-id-value")).toHaveText(firstBody.draftId);
  await expect(page.getByTestId("workflow-draft-state")).toContainText("DRAFT");
  expect(creates).toHaveLength(1);

  // The same read failure after an edit recovers the applied edit by read, even
  // though the browser still holds the earlier revision until a read succeeds.
  refuseRead = true;
  await page.getByTestId("workflow-edit-payload").fill('{"parcelAddress":"Edited before read failure"}');
  await page.getByTestId("workflow-edit-save").click();
  await expect(page.getByTestId("workflow-error-code")).toHaveText("UPSTREAM_UNAVAILABLE");
  await expect(page.getByTestId("workflow-draft-revision")).toHaveText("1");
  expect(edits).toHaveLength(1);
  await page.getByTestId("workflow-edit-save").click();
  await expect(page.getByTestId("workflow-draft-revision")).toHaveText("2");
  await expect(page.getByTestId("workflow-draft-payload")).toContainText("Edited before read failure");
  expect(edits).toHaveLength(1);
});

test("an unrelated draft read never acknowledges another draft's completed attempt", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  await signIn(page, WORKER);
  const unrelatedId = await createDraft(page, "SYNTHETIC-W10");

  await page.goto("/admin/workflow");
  const keys: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/v2/admin/workflow/drafts")) {
      keys.push(request.headers()["idempotency-key"] ?? "");
    }
  });
  let refuseRead = true;
  await page.route("**/v2/admin/workflow/drafts/*", async route => {
    if (route.request().method() === "GET" && refuseRead) {
      refuseRead = false;
      await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "UPSTREAM_UNAVAILABLE" }) });
    } else await route.continue();
  });
  await page.getByTestId("workflow-create-record").fill("SYNTHETIC-W11");
  await page.getByTestId("workflow-create-payload").fill(UPSERT_PAYLOAD);
  const created = () => page.waitForResponse(response => response.request().method() === "POST"
    && response.url().endsWith("/v2/admin/workflow/drafts"));
  const [first] = await Promise.all([created(), page.getByTestId("workflow-create-submit").click()]);
  const firstBody = await first.json();
  expect(first.status()).toBe(201);
  await expect(page.getByTestId("workflow-error-code")).toHaveText("UPSTREAM_UNAVAILABLE");
  expect(keys).toHaveLength(1);

  // Opening an unrelated draft succeeds, but it must not acknowledge the other
  // draft's completed attempt.
  await page.getByTestId("workflow-draft-id").fill(unrelatedId);
  await page.getByTestId("workflow-load-draft").click();
  await expect(page.getByTestId("workflow-draft-id-value")).toHaveText(unrelatedId);
  await expect(page.getByTestId("workflow-attempt")).toHaveCount(1);
  // This session only knows the prepared attempt locally; the unrelated read
  // neither acknowledged it nor learned its outcome.
  await expect(page.getByTestId("workflow-attempt")).toHaveAttribute("data-state", "PREPARED");

  // The unchanged retry recovers the same draft and never creates a second one.
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-draft-id-value")).toHaveText(firstBody.draftId);
  await expect(page.getByTestId("workflow-attempt")).toHaveCount(0);
  expect(keys).toHaveLength(1);
  expect(keys[0]).not.toBe("");
});

test("a draft-only session is not offered a draft it cannot read back", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  let signedIn = false;
  await page.route("**/api/admin/session", async route => {
    if (route.request().method() !== "GET") { signedIn = true; await route.continue(); return; }
    if (!signedIn) {
      await route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ code: "SESSION_REQUIRED" }) });
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
      username: "registry_worker", role: "registry_worker", csrfToken: "synthetic-csrf-token",
      permissions: ["records.draft"], registryIds: ["gov.registry.land"], deploymentRegistryId: "gov.registry.land",
    }) });
  });
  await signIn(page, WORKER);
  await page.goto("/admin/workflow");
  await expect(page.getByTestId("workflow-grants")).toHaveText("records.draft");
  await expect(page.getByTestId("workflow-no-read")).toBeVisible();
  // Creating would produce a draft this session cannot read back, so the
  // mutation controls stay hidden and the input stays disabled.
  await expect(page.getByTestId("workflow-create-form")).toHaveCount(0);
  await expect(page.getByTestId("workflow-create-unavailable")).toBeVisible();
  await expect(page.getByTestId("workflow-create-unavailable")).toContainText("records.read");
  await expect(page.getByTestId("workflow-load-draft")).toBeDisabled();
});

test("a malformed session DTO fails the whole session closed", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  await page.route("**/api/admin/session", async route => {
    if (route.request().method() !== "GET") { await route.continue(); return; }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
      username: 7, role: "registry_worker", csrfToken: "synthetic-csrf-token",
      permissions: ["records.read", "records.draft"], registryIds: ["gov.registry.land"],
      deploymentRegistryId: "gov.registry.land",
    }) });
  });
  await page.goto("/admin");
  // A wrong-typed identity field is never a half-usable session: nothing is
  // trusted and the shell asks for a clean sign-in instead.
  await expect(page.getByTestId("login-username")).toBeVisible();
  await expect(page.getByTestId("session-summary")).toHaveCount(0);
  await expect(page.getByTestId("nav-workflow")).toHaveCount(0);
});

test("an OIDC start follows only absolute https or loopback http authorization URLs", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  const answers: Array<{ authorizationUrl?: unknown }> = [
    { authorizationUrl: "javascript:alert(1)" },
    { authorizationUrl: "data:text/html,<b>idp</b>" },
    { authorizationUrl: "http://idp.example.test/authorize" },
    { authorizationUrl: "https://demo:password@idp.example.test/authorize" },
    {},
  ];
  let startCalls = 0;
  await page.route("**/v2/admin/oidc/config", route => route.fulfill({
    status: 200, contentType: "application/json", body: JSON.stringify({ enabled: true }),
  }));
  await page.route("**/v2/admin/oidc/start", async route => {
    const body = answers[startCalls] ?? {};
    startCalls += 1;
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.goto("/admin");
  await expect(page.getByTestId("oidc-signin")).toBeVisible();
  const appOrigin = new URL(page.url()).origin;

  // Script, data, remote http, password-bearing and missing URLs are refused:
  // the English error appears and the page stays on the app protocol and host.
  for (let index = 0; index < answers.length; index += 1) {
    await page.getByTestId("oidc-signin").click();
    await expect.poll(() => startCalls).toBe(index + 1);
    await expect(page.getByTestId("oidc-signin")).toBeEnabled();
    await expect(page.getByTestId("login-error")).toContainText("authorization URL");
    expect(new URL(page.url()).origin).toBe(appOrigin);
  }

  // The loopback HTTP IdP the server policy allows for tests is followed.
  answers.push({ authorizationUrl: "http://127.0.0.1:9/authorize" });
  await page.route("http://127.0.0.1:9/**", route => route.fulfill({
    status: 200, contentType: "text/html", body: "<html>synthetic loopback IdP</html>",
  }));
  await page.getByTestId("oidc-signin").click();
  await page.waitForURL("http://127.0.0.1:9/authorize");
  expect(new URL(page.url()).protocol).toBe("http:");

  // A configured HTTPS provider is followed from any host.
  answers.push({ authorizationUrl: "https://idp.example.test/authorize" });
  await page.route("https://idp.example.test/**", route => route.fulfill({
    status: 200, contentType: "text/html", body: "<html>synthetic configured IdP</html>",
  }));
  await page.goto("/admin");
  await expect(page.getByTestId("oidc-signin")).toBeVisible();
  await page.getByTestId("oidc-signin").click();
  await page.waitForURL("https://idp.example.test/authorize");
  expect(new URL(page.url()).protocol).toBe("https:");
});

test("a non-JSON workflow answer is reported as unreadable and stays retryable", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  await signIn(page, WORKER);
  await page.goto("/admin/workflow");
  const attemptKeys: string[] = [];
  await page.route("**/v2/admin/workflow/drafts", async route => {
    if (route.request().method() === "POST") {
      attemptKeys.push(route.request().headers()["idempotency-key"] ?? "");
      if (attemptKeys.length === 1) {
        await route.fulfill({ status: 200, contentType: "text/html", body: "<html>gateway intercept</html>" });
      } else await route.continue();
    } else await route.continue();
  });
  await page.getByTestId("workflow-create-record").fill("SYNTHETIC-W12");
  await page.getByTestId("workflow-create-payload").fill(UPSERT_PAYLOAD);
  await page.getByTestId("workflow-create-submit").click();
  // The unreadable answer is uncertain by definition: the message must say so
  // and must not claim the attempt failed.
  await expect(page.getByTestId("workflow-error-code")).toHaveText("RESPONSE_NOT_JSON");
  await expect(page.getByTestId("workflow-error")).toContainText("cannot confirm whether the action completed");
  await expect(page.getByTestId("workflow-error")).toContainText("Retry the same attempt unchanged");
  await expect(page.getByTestId("workflow-error")).toContainText("the server keeps the pending attempt");
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("DRAFT");
  expect(attemptKeys).toHaveLength(2);
  expect(attemptKeys[0]).not.toBe("");
  expect(attemptKeys[1]).toBe(attemptKeys[0]);

  // Once this exact draft has been read successfully, a new explicit create
  // is a fresh attempt rather than a replay of the completed request.
  const confirmedDraft = await page.getByTestId("workflow-draft-id-value").innerText();
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-draft-id-value")).not.toHaveText(confirmedDraft);
  expect(attemptKeys).toHaveLength(3);
  expect(attemptKeys[2]).not.toBe(attemptKeys[1]);
});

test("a lost 201 is recovered from the durable attempt after a reload", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  await signIn(page, WORKER);
  await page.goto("/admin/workflow");
  let lost = false;
  await page.route("**/v2/admin/workflow/drafts", async route => {
    if (route.request().method() !== "POST" || lost) { await route.continue(); return; }
    lost = true;
    // The server applies the create, but the browser never sees the 201.
    await route.fetch();
    await route.abort("failed");
  });
  await page.getByTestId("workflow-create-record").fill("SYNTHETIC-W13");
  await page.getByTestId("workflow-create-payload").fill(UPSERT_PAYLOAD);
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-error-code")).toHaveText("REQUEST_FAILED");
  // No draft is shown, and the local row only knows what the prepare answered.
  await expect(page.getByTestId("workflow-draft")).toHaveCount(0);
  await expect(page.getByTestId("workflow-attempt")).toHaveAttribute("data-state", "PREPARED");

  // The manual refresh asks the server: the same attempt is completed.
  await page.getByTestId("workflow-attempts-refresh").click();
  await expect(page.getByTestId("workflow-attempt")).toHaveAttribute("data-state", "COMPLETED");
  await expect(page.getByTestId("workflow-attempt-open")).toBeVisible();
  const draftId = await page.getByTestId("workflow-attempt").getAttribute("data-draft-id");
  expect(draftId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

  // A reload lists the durable attempt at startup; nothing is opened or
  // retried by itself.
  await page.reload();
  await expect(page.getByTestId("workflow-attempt")).toHaveCount(1);
  await expect(page.getByTestId("workflow-attempt")).toHaveAttribute("data-state", "COMPLETED");
  await expect(page.getByTestId("workflow-draft")).toHaveCount(0);

  await page.getByTestId("workflow-attempt-open").click();
  await expect(page.getByTestId("workflow-draft-id-value")).toHaveText(draftId as string);
  await expect(page.getByTestId("workflow-draft-state")).toContainText("DRAFT");
  // The validated read acknowledges the attempt, so the list is empty again.
  await expect(page.getByTestId("workflow-attempt")).toHaveCount(0);
  await page.reload();
  await expect(page.getByTestId("workflow-attempts-empty")).toBeVisible();
  await expect(page.getByTestId("workflow-draft")).toHaveCount(0);
});

test("a prepared attempt keeps its server key and is reused after a reload", async ({ page }) => {
  await scenario(page, { resetWorkflow: true, workflowUnavailableOnce: true });
  const keys: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/v2/admin/workflow/drafts")) {
      keys.push(request.headers()["idempotency-key"] ?? "");
    }
  });
  await signIn(page, WORKER);
  await page.goto("/admin/workflow");
  await page.getByTestId("workflow-create-record").fill("SYNTHETIC-W14");
  await page.getByTestId("workflow-create-payload").fill(UPSERT_PAYLOAD);
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-error-code")).toHaveText("UPSTREAM_UNAVAILABLE");
  expect(keys).toHaveLength(1);
  expect(keys[0]).not.toBe("");

  // The durable attempt survives the reload and is listed as prepared.
  await page.reload();
  await expect(page.getByTestId("workflow-attempt")).toHaveCount(1);
  await expect(page.getByTestId("workflow-attempt")).toHaveAttribute("data-state", "PREPARED");
  await expect(page.getByTestId("workflow-attempt")).toHaveAttribute("data-action", "create");
  await expect(page.getByTestId("workflow-attempt-prepared")).toBeVisible();
  await expect(page.getByTestId("workflow-draft")).toHaveCount(0);

  // Re-entering the same body reuses the durable attempt's key, and only then
  // does the mutation run.
  await page.getByTestId("workflow-create-record").fill("SYNTHETIC-W14");
  await page.getByTestId("workflow-create-payload").fill(UPSERT_PAYLOAD);
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("DRAFT");
  expect(keys).toHaveLength(2);
  expect(keys[1]).toBe(keys[0]);
  await expect(page.getByTestId("workflow-attempt")).toHaveCount(0);
});

test("only a prepared attempt can be cancelled explicitly and its key is never replayed", async ({ page }) => {
  await scenario(page, { resetWorkflow: true, workflowUnavailableOnce: true });
  const keys: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/v2/admin/workflow/drafts")) {
      keys.push(request.headers()["idempotency-key"] ?? "");
    }
  });
  await signIn(page, WORKER);
  await page.goto("/admin/workflow");
  await page.getByTestId("workflow-create-record").fill("SYNTHETIC-W15");
  await page.getByTestId("workflow-create-payload").fill(UPSERT_PAYLOAD);
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-error-code")).toHaveText("UPSTREAM_UNAVAILABLE");
  await expect(page.getByTestId("workflow-attempt")).toHaveAttribute("data-state", "PREPARED");
  // A prepared attempt offers the explicit cancel; a completed one never does.
  await expect(page.getByTestId("workflow-attempt-cancel")).toBeVisible();
  await expect(page.getByTestId("workflow-attempt-open")).toHaveCount(0);
  expect(keys).toHaveLength(1);

  // Nothing is cancelled silently, and the list is refreshed afterwards.
  await page.getByTestId("workflow-attempt-cancel").click();
  await expect(page.getByTestId("workflow-attempt")).toHaveCount(0);
  await expect(page.getByTestId("workflow-attempts-empty")).toBeVisible();
  await expect(page.getByTestId("workflow-draft")).toHaveCount(0);
  expect(keys).toHaveLength(1);

  // The same body after the explicit cancel is a new attempt with a new key,
  // never a replay of the cancelled one.
  await page.getByTestId("workflow-create-submit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("DRAFT");
  expect(keys).toHaveLength(2);
  expect(keys[1]).not.toBe(keys[0]);
});

test("a read-only session lists readable drafts and opens one without mutation controls", async ({ browser }) => {
  const workerContext = await browser.newContext();
  const auditorContext = await browser.newContext();
  const worker = await workerContext.newPage();
  const auditor = await auditorContext.newPage();
  try {
    await scenario(worker, { resetWorkflow: true });
    await signIn(worker, WORKER);
    const draftId = await createDraft(worker, "SYNTHETIC-W16");
    await worker.getByTestId("workflow-submit").click();
    await expect(worker.getByTestId("workflow-draft-state")).toContainText("SUBMITTED");

    await signIn(auditor, AUDITOR);
    await auditor.goto("/admin/workflow");
    const row = auditor.getByTestId("workflow-draft-row").filter({ hasText: "SYNTHETIC-W16" });
    await expect(row).toBeVisible();
    await expect(row).toHaveAttribute("data-state", "SUBMITTED");
    // The list is read-only: no create or edit controls are offered here.
    await expect(auditor.getByTestId("workflow-create-form")).toHaveCount(0);
    await expect(auditor.getByTestId("workflow-edit-form")).toHaveCount(0);

    await row.getByTestId("workflow-draft-open").click();
    await expect(auditor.getByTestId("workflow-draft-id-value")).toHaveText(draftId);
    await expect(auditor.getByTestId("workflow-draft-state")).toContainText("SUBMITTED");
    await expect(auditor.getByTestId("workflow-approve")).toBeDisabled();
    await expect(auditor.getByTestId("workflow-submit")).toBeDisabled();
  } finally {
    await workerContext.close();
    await auditorContext.close();
  }
});

test("an approver finds and opens a submitted draft from the list without a UUID", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  await signIn(page, WORKER);
  const draftId = await createDraft(page, "SYNTHETIC-W17");
  await page.getByTestId("workflow-submit").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("SUBMITTED");
  const hash = await page.getByTestId("workflow-draft-payload-hash").innerText();

  await signOut(page);
  await signIn(page, APPROVER);
  await page.goto("/admin/workflow");
  const row = page.getByTestId("workflow-draft-row").filter({ hasText: "SYNTHETIC-W17" });
  await expect(row).toBeVisible();
  // The approver never types the UUID: the list row is the entry point.
  await expect(page.getByTestId("workflow-draft-id")).toHaveValue("");
  await row.getByTestId("workflow-draft-open").click();
  await expect(page.getByTestId("workflow-draft-id-value")).toHaveText(draftId);
  await expect(page.getByTestId("workflow-draft-payload-hash")).toHaveText(hash);
  await page.getByTestId("workflow-approve").click();
  await expect(page.getByTestId("workflow-draft-state")).toContainText("APPROVED");
  await expect(page.getByTestId("workflow-draft-approver")).toHaveText("registry_approver");
});

test("the draft list follows the server cursor and a missing list route never blocks the workspace", async ({ page }) => {
  await scenario(page, { resetWorkflow: true });
  await signIn(page, WORKER);
  const first = "11111111-1111-4111-8111-111111111111";
  const second = "22222222-2222-4222-8222-222222222222";
  const row = (draftId: string, recordId: string) => ({
    draft_id: draftId, record_id: recordId, creator: "registry_worker", revision: 1, base_version: 0,
    state: "SUBMITTED", approver: null, committed_version: null, payload_hash: "a".repeat(64), operation: "upsert",
  });
  const pages = [
    { drafts: [row(first, "SYNTHETIC-W18")], nextCursor: second },
    { drafts: [row(second, "SYNTHETIC-W19")], nextCursor: null },
  ];
  let missing = false;
  await page.route(/\/v2\/admin\/workflow\/drafts(\?after=[0-9a-f-]{36})?$/, async route => {
    if (route.request().method() !== "GET") { await route.continue(); return; }
    if (missing) {
      await route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: "NOT_FOUND" }) });
      return;
    }
    // The page is selected by the cursor: the first page has no cursor, and
    // only the cursor of the last row continues the list.
    const after = new URL(route.request().url()).searchParams.get("after");
    const answer = after === second ? pages[1] : pages[0];
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(answer) });
  });
  await page.goto("/admin/workflow");
  await expect(page.getByTestId("workflow-draft-row")).toHaveCount(1);
  await expect(page.getByTestId("workflow-draft-row")).toContainText("SYNTHETIC-W18");
  await page.getByTestId("workflow-draft-list-next").click();
  await expect(page.getByTestId("workflow-draft-row")).toHaveCount(2);
  await expect(page.getByTestId("workflow-draft-row").nth(1)).toContainText("SYNTHETIC-W19");
  // The last page carries no cursor, so it is not offered again.
  await expect(page.getByTestId("workflow-draft-list-next")).toHaveCount(0);

  // An older server build answers 404 for the list; only the list box says so,
  // and the UUID workspace keeps working.
  missing = true;
  await page.getByTestId("workflow-draft-list-refresh").click();
  await expect(page.getByTestId("workflow-draft-list-unavailable")).toBeVisible();
  await expect(page.getByTestId("workflow-draft-row")).toHaveCount(0);
  await expect(page.getByTestId("workflow-create-form")).toBeVisible();
  await page.getByTestId("workflow-draft-id").fill("33333333-3333-4333-8333-333333333333");
  await page.getByTestId("workflow-load-draft").click();
  await expect(page.getByTestId("workflow-error-code")).toHaveText("DRAFT_NOT_FOUND");
});

test("a mismatched prepared receipt sends no workflow mutation",async({page})=>{
  await scenario(page,{resetWorkflow:true});
  await signIn(page,WORKER);
  await page.goto('/admin/workflow');
  let mutations=0;
  page.on('request',request=>{if(request.method()==='POST'&&request.url().endsWith('/v2/admin/workflow/drafts')) mutations++;});
  await page.route('**/v2/admin/workflow/attempts',async route=>{
    if(route.request().method()!=='POST') {await route.continue();return;}
    const response=await route.fetch(),body=await response.json();
    await route.fulfill({response,json:{...body,idempotencyKey:'00000000-0000-0000-0000-000000000000'}});
  });
  await page.getByTestId('workflow-create-record').fill('SYNTHETIC-BAD-RECEIPT');
  await page.getByTestId('workflow-create-submit').click();
  await expect(page.getByTestId('workflow-error-code')).toHaveText('ATTEMPT_RESPONSE_INVALID');
  expect(mutations).toBe(0);
  await expect(page.getByTestId('workflow-draft')).toHaveCount(0);
});

test("a malformed commit receipt remains recoverable and never renders NaN evidence",async({page})=>{
  await scenario(page,{resetWorkflow:true});
  await signIn(page,WORKER);
  const id=await createDraft(page,'SYNTHETIC-BAD-COMMIT');
  await page.getByTestId('workflow-submit').click();
  await expect(page.getByTestId('workflow-draft-state')).toContainText('SUBMITTED');
  await signOut(page);await signIn(page,APPROVER);await loadDraft(page,id);
  await page.getByTestId('workflow-approve').click();
  await expect(page.getByTestId('workflow-draft-state')).toContainText('APPROVED');
  await signOut(page);await signIn(page,WORKER);await loadDraft(page,id);
  await page.route('**/v2/admin/workflow/drafts/*/commit',async route=>{
    const response=await route.fetch(),body=await response.json();
    await route.fulfill({response,json:{...body,committed:{}}});
  });
  await page.getByTestId('workflow-commit').click();
  await expect(page.getByTestId('workflow-error-code')).toHaveText('DRAFT_RESPONSE_INVALID');
  await expect(page.getByTestId('workflow-committed-note')).toHaveCount(0);
  await expect(page.getByTestId('workflow-panel')).not.toContainText('NaN');
  await page.reload();
  await expect(page.getByTestId('workflow-attempt')).toHaveAttribute('data-state','COMPLETED');
  await page.getByTestId('workflow-attempt-open').click();
  await expect(page.getByTestId('workflow-draft-state')).toContainText('COMMITTED');
  await expect(page.getByTestId('workflow-draft-committed-version')).toHaveText('1');
  await expect(page.getByTestId('workflow-attempt')).toHaveCount(0);
});
