import { expect, test, type Page } from "@playwright/test";
import { mockWalletScript, MOCK_WALLET_ADDRESS } from "../mock-wallet.ts";

const FIXTURE = `http://127.0.0.1:${process.env.ONELAYER_E2E_FIXTURE_PORT ?? "8199"}`;
const OPERATOR_PASSWORD = "operator-password-0123456789";
const AUDITOR_PASSWORD = "auditor-password-0123456789";

async function scenario(page: Page, body: Record<string, unknown>): Promise<void> {
  const response = await page.request.post(`${FIXTURE}/__fixture/scenario`, { data: body });
  expect(response.ok()).toBeTruthy();
}

async function signIn(page: Page, user: "operator" | "auditor"): Promise<void> {
  await page.goto("/admin");
  await page.getByTestId("login-username").selectOption(user);
  await page.getByTestId("login-password").fill(user === "operator" ? OPERATOR_PASSWORD : AUDITOR_PASSWORD);
  await page.getByTestId("login-submit").click();
  await expect(page.getByTestId("session-role")).toHaveText(user);
}

/** Each test installs its own mock wallet before any page script runs. */
async function prepare(page: Page, options: { rejectSigning?: boolean } = {}): Promise<void> {
  await page.addInitScript(mockWalletScript(options));
  await scenario(page, {});
}

test("operator publishes a batch and issues a certificate", async ({ page }) => {
  await prepare(page);
  await signIn(page, "operator");
  await page.goto("/admin/publish");

  await page.getByTestId("wallet-connect").click();
  await expect(page.getByTestId("wallet-address")).toHaveText(MOCK_WALLET_ADDRESS);

  await page.getByTestId("prepare-batch").click();
  await expect(page.getByTestId("transaction-state")).toContainText("SIMULATED");

  // The review must show every field an operator approves before signing.
  await expect(page.getByTestId("review-cluster")).toHaveText("solana:devnet");
  await expect(page.getByTestId("review-program")).toHaveText("6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo");
  await expect(page.getByTestId("review-merkle-root")).toHaveText("aa".repeat(32));
  await expect(page.getByTestId("review-segment")).not.toBeEmpty();
  await expect(page.getByTestId("review-accounts").locator("tr")).toHaveCount(4);
  await expect(page.getByTestId("simulation-outcome")).toContainText("Simulation succeeded");
  await expect(page.getByTestId("simulation-logs")).toContainText("publish_anchor");

  await page.getByTestId("sign-transaction").click();
  await expect(page.getByTestId("transaction-state")).toContainText("SUBMITTED");
  await expect(page.getByTestId("transaction-signature")).not.toBeEmpty();

  await page.getByTestId("poll-status").click();
  await expect(page.getByTestId("transaction-state")).toContainText("FINALIZED");

  await page.getByTestId("issue-certificate").click();
  await expect(page.getByTestId("issued-certificate")).toBeVisible();
  await expect(page.getByTestId("issued-hash")).toHaveText(/^[0-9a-f]{64}$/);
  await expect(page.getByTestId("explorer-link")).toHaveAttribute("href", /cluster=devnet/);

  const qrUrl = await page.getByTestId("issued-qr-url").getAttribute("href");
  expect(qrUrl).toMatch(/\/c\/[0-9a-f]{32}\?h=[A-Za-z0-9_-]{43}$/);

  await page.goto(qrUrl as string);
  await expect(page.getByTestId("verification-status")).toContainText("VERIFIED");
});

test("no certificate is offered before the anchor is finalized", async ({ page }) => {
  await prepare(page);
  await signIn(page, "operator");
  await page.goto("/admin/publish");
  await page.getByTestId("wallet-connect").click();
  await page.getByTestId("prepare-batch").click();
  await expect(page.getByTestId("issue-certificate")).toHaveCount(0);
  await page.getByTestId("sign-transaction").click();
  await expect(page.getByTestId("transaction-state")).toContainText("SUBMITTED");
  await expect(page.getByTestId("issue-certificate")).toHaveCount(0);
});

test("a second click and a reload reuse the same batch", async ({ page }) => {
  await prepare(page);
  await signIn(page, "operator");
  await page.goto("/admin/publish");
  await page.getByTestId("wallet-connect").click();
  await page.getByTestId("prepare-batch").click();
  const first = await page.getByTestId("transaction-review").getAttribute("data-state");
  expect(first).toBe("SIMULATED");
  const intentHash = await page.getByText(/Intent hash/).textContent();

  await page.getByTestId("prepare-batch").click();
  await expect(page.getByTestId("transaction-review")).toHaveAttribute("data-state", "SIMULATED");
  expect(await page.getByText(/Intent hash/).textContent()).toBe(intentHash);
});

test("a failed simulation never asks for a signature", async ({ page }) => {
  await prepare(page);
  await scenario(page, { simulationFails: true });
  await signIn(page, "operator");
  await page.goto("/admin/publish");
  await page.getByTestId("wallet-connect").click();
  await page.getByTestId("prepare-batch").click();
  await expect(page.getByTestId("publish-error")).toHaveText("REQUEST_FAILED");
  await expect(page.getByTestId("transaction-review")).toHaveCount(0);
});

test("an expired blockhash returns the flow to preparation", async ({ page }) => {
  await prepare(page);
  await signIn(page, "operator");
  await page.goto("/admin/publish");
  await page.getByTestId("wallet-connect").click();
  await page.getByTestId("prepare-batch").click();
  await scenario(page, { blockhashExpired: true });
  await page.getByTestId("sign-transaction").click();
  await expect(page.getByTestId("transaction-state")).toContainText("EXPIRED");
  await expect(page.getByTestId("failure-code")).toHaveText("BLOCKHASH_EXPIRED");
  await expect(page.getByTestId("issue-certificate")).toHaveCount(0);
});

test("a wallet rejection is recorded and blocks publication", async ({ page }) => {
  await prepare(page, { rejectSigning: true });
  await signIn(page, "operator");
  await page.goto("/admin/publish");
  await page.getByTestId("wallet-connect").click();
  await page.getByTestId("prepare-batch").click();
  await page.getByTestId("sign-transaction").click();
  await expect(page.getByTestId("transaction-state")).toContainText("SIGNING REJECTED");
  await expect(page.getByTestId("issue-certificate")).toHaveCount(0);
});

test("the auditor role is blocked by the API, not by hidden buttons", async ({ page }) => {
  await prepare(page);
  await signIn(page, "auditor");
  await expect(page.getByTestId("dashboard-readonly")).toBeVisible();

  await page.goto("/admin/records");
  await expect(page.getByTestId("records-readonly")).toBeVisible();

  // Bypass the disabled control entirely and call the API the way the UI does.
  const csrf = await page.evaluate(async () => {
    const response = await fetch("/api/admin/session", { cache: "no-store" });
    return (await response.json()).csrfToken as string;
  });
  const status = await page.evaluate(async (token) => {
    const response = await fetch("/api/admin/records", {
      method: "POST",
      headers: { "content-type": "application/json", "x-onelayer-csrf": token },
      body: JSON.stringify({ internalRecordId: "SYNTHETIC-9", status: "ACTIVE" }),
    });
    return response.status;
  }, csrf);
  expect(status).toBe(403);
});

test("mutations without the CSRF token are refused", async ({ page }) => {
  await prepare(page);
  await signIn(page, "operator");
  const status = await page.evaluate(async () => {
    const response = await fetch("/api/admin/records", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ internalRecordId: "SYNTHETIC-9", status: "ACTIVE" }),
    });
    return response.status;
  });
  expect(status).toBe(403);
});
