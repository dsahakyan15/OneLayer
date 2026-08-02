import { expect, test, type Page } from "@playwright/test";
import { mockWalletScript } from "../mock-wallet.ts";

const FIXTURE = `http://127.0.0.1:${process.env.ONELAYER_E2E_FIXTURE_PORT ?? "8199"}`;
const OPERATOR_PASSWORD = "operator-password-0123456789";

async function scenario(page: Page, body: Record<string, unknown>): Promise<void> {
  expect((await page.request.post(`${FIXTURE}/__fixture/scenario`, { data: body })).ok()).toBeTruthy();
}

/** Issues a certificate through the Admin flow and returns its QR URL. */
async function issueCertificate(page: Page): Promise<string> {
  await page.addInitScript(mockWalletScript());
  await page.goto("/admin");
  await page.getByTestId("login-username").selectOption("operator");
  await page.getByTestId("login-password").fill(OPERATOR_PASSWORD);
  await page.getByTestId("login-submit").click();
  await page.goto("/admin/publish");
  await page.getByTestId("wallet-connect").click();
  await page.getByTestId("prepare-batch").click();
  await page.getByTestId("sign-transaction").click();
  await page.getByTestId("poll-status").click();
  await expect(page.getByTestId("transaction-state")).toContainText("FINALIZED");
  await page.getByTestId("issue-certificate").click();
  const qrUrl = await page.getByTestId("issued-qr-url").getAttribute("href");
  return qrUrl as string;
}

test.beforeEach(async ({ page }) => {
  await scenario(page, {});
});

test("a scanned certificate URL verifies", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await page.goto(qrUrl);
  await expect(page.getByTestId("verification-status")).toContainText("VERIFIED");
  await expect(page.getByTestId("incident-index-status")).toContainText("INDEX CHECKED");
});

test("manual input reaches the same result as the QR link", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await page.goto("/verify");
  await page.getByTestId("mode-manual").click();
  await page.getByTestId("manual-input").fill(qrUrl);
  await page.getByTestId("manual-submit").click();
  await expect(page.getByTestId("verification-status")).toContainText("VERIFIED");
});

test("a tampered QR hash is INVALID before any chain lookup", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  const tampered = qrUrl.replace(/h=(.)/, (match, first: string) => `h=${first === "A" ? "B" : "A"}`);
  await page.goto(tampered);
  await expect(page.getByTestId("verification-status")).toContainText("INVALID");
  await expect(page.getByTestId("verification-code")).toHaveText("QR_HASH_MISMATCH");
});

test("a tampered package is INVALID", async ({ page }) => {
  await page.goto("/verify");
  await page.getByTestId("mode-manual").click();
  await page.getByTestId("manual-input").fill("Q0VSVElGSUNBVEUtUEFDS0FHRS1UQU1QRVJFRA");
  await page.getByTestId("manual-submit").click();
  await expect(page.getByTestId("verification-status")).toContainText("INVALID");
});

test("direct database tampering shows DISPUTED, not a green result", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, {
    verification: {
      status: "DISPUTED",
      certificateId: "0".repeat(31) + "1",
      batchSequence: "1",
      solanaSlot: "412346000",
      incidentIndexStatus: "CHECKED",
      indexedThroughSlot: "412346040",
      rpcFinalizedHeadSlot: "412346050",
      indexLagSlots: "10",
      warnings: [],
    },
  });
  await page.goto(qrUrl);
  await expect(page.getByTestId("verification-status")).toContainText("DISPUTED");
  await expect(page.getByTestId("verification-result")).toHaveAttribute("data-status", "DISPUTED");
});

test("a stale incident index never shows a green VERIFIED", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, {
    verification: {
      status: "VERIFIED_NO_INCIDENT_CHECK",
      certificateId: "0".repeat(31) + "1",
      batchSequence: "1",
      solanaSlot: "412346000",
      incidentIndexStatus: "STALE",
      indexedThroughSlot: "412000000",
      rpcFinalizedHeadSlot: "412346050",
      indexLagSlots: "346050",
      warnings: ["Incident index is stale."],
    },
  });
  await page.goto(qrUrl);
  await expect(page.getByTestId("verification-status")).toContainText("NO INCIDENT CHECK");
  await expect(page.getByTestId("verification-status")).not.toContainText(/^VERIFIED$/);
  await expect(page.getByTestId("incident-index-status")).toContainText("INDEX STALE");
});

test("historical and superseded lifecycles have their own result views", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, {
    verification: {
      status: "VERIFIED_HISTORICAL",
      certificateId: "0".repeat(31) + "1",
      batchSequence: "1",
      incidentIndexStatus: "CHECKED",
      recordVersion: "1",
      currentRecordVersion: "3",
      certificateLifecycle: "ACTIVE",
      code: "RECORD_SUPERSEDED",
      warnings: ["A newer version of this record exists."],
    },
  });
  await page.goto(qrUrl);
  await expect(page.getByTestId("verification-status")).toContainText("HISTORICAL");
  await expect(page.getByTestId("verification-explanation")).toContainText("newer version");

  await scenario(page, {
    verification: {
      status: "SUPERSEDED",
      certificateId: "0".repeat(31) + "1",
      batchSequence: "1",
      incidentIndexStatus: "CHECKED",
      certificateLifecycle: "SUPERSEDED",
      code: "RECORD_SUPERSEDED",
      warnings: [],
    },
  });
  await page.goto(qrUrl);
  await expect(page.getByTestId("verification-status")).toContainText("SUPERSEDED");
});

test("camera denial never blocks image upload or manual input", async ({ page, context }) => {
  await context.clearPermissions();
  await page.goto("/verify");
  await page.getByTestId("mode-camera").click();
  await expect(page.getByTestId("camera-error")).toBeVisible();
  await page.getByTestId("mode-manual").click();
  await expect(page.getByTestId("manual-input")).toBeVisible();
  await page.getByTestId("mode-image").click();
  await expect(page.getByTestId("qr-image-input")).toBeVisible();
});

test("a QR link without a hash refuses to verify", async ({ page }) => {
  await page.goto(`/c/${"0".repeat(31)}1`);
  await expect(page.getByTestId("qr-hash-missing")).toBeVisible();
});

test("status is conveyed by icon and text, and the page is keyboard operable", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await page.goto(qrUrl);
  const badge = page.getByTestId("verification-status");
  await expect(badge).toContainText("VERIFIED");
  // The icon is decorative; the label carries the meaning.
  expect(await badge.locator("[aria-hidden='true']").count()).toBe(1);
  await expect(page.getByTestId("verification-explanation")).not.toBeEmpty();

  await page.goto("/verify");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Tab");
  const focused = await page.evaluate(() => document.activeElement?.tagName ?? "");
  expect(["BUTTON", "A", "INPUT", "SELECT"]).toContain(focused);
});

test("the optional light theme reuses the same state and layout", async ({ page }) => {
  await page.goto("/verify");
  await page.getByTestId("theme-toggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.getByTestId("mode-manual").click();
  await expect(page.getByTestId("manual-input")).toBeVisible();
});
