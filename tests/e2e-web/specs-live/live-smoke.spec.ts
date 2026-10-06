import { expect, test } from "@playwright/test";

// The certificate under test was anchored by the guarded CLI publish, so no key
// material is ever placed in the browser. This spec proves only the public
// path: QR URL → finalized anchor → proofs verified, never a current claim.
const qrUrl = process.env.ONELAYER_LIVE_QR_URL;

test("a live devnet certificate proves the anchor without claiming current status", async ({ page }) => {
  expect(qrUrl, "ONELAYER_LIVE_QR_URL must be set by the smoke-test caller").toBeTruthy();
  await page.goto(qrUrl as string);
  // The live stack must answer with the v2 envelope: proof of the anchored
  // package, and no current verdict while the lifecycle source is unauthenticated.
  await expect(page.getByTestId("verification-result")).toHaveAttribute("data-result-version", "2", { timeout: 120_000 });
  await expect(page.getByTestId("proofs-status")).toContainText("PROOFS VERIFIED");
  await expect(page.getByTestId("verification-status")).not.toHaveAttribute("data-tone", "ok");
  await expect(page.getByTestId("lifecycle-status")).not.toBeEmpty();
  await expect(page.getByTestId("incident-index-status")).not.toBeEmpty();
  await page.screenshot({ path: "../../deploy/devnet-demo/artifacts/live-smoke/verified.png", fullPage: true });
});

test("a tampered QR hash is refused on the live stack", async ({ page }) => {
  const tampered = (qrUrl as string).replace(/h=(.)/, (_match, first: string) => `h=${first === "A" ? "B" : "A"}`);
  await page.goto(tampered);
  await expect(page.getByTestId("verification-status")).toContainText("INVALID");
});
