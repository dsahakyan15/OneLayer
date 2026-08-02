import { expect, test } from "@playwright/test";

// The certificate under test was anchored by the guarded CLI publish, so no key
// material is ever placed in the browser. This spec proves only the public
// path: QR URL → finalized anchor → VERIFIED.
const qrUrl = process.env.ONELAYER_LIVE_QR_URL;

test("a live devnet certificate verifies in the browser", async ({ page }) => {
  expect(qrUrl, "ONELAYER_LIVE_QR_URL must be set by the live-smoke script").toBeTruthy();
  await page.goto(qrUrl as string);
  await expect(page.getByTestId("verification-status")).toContainText("VERIFIED", { timeout: 120_000 });
  await expect(page.getByTestId("incident-index-status")).not.toBeEmpty();
  await page.screenshot({ path: "../../deploy/devnet-demo/artifacts/live-smoke/verified.png", fullPage: true });
});

test("a tampered QR hash is refused on the live stack", async ({ page }) => {
  const tampered = (qrUrl as string).replace(/h=(.)/, (_match, first: string) => `h=${first === "A" ? "B" : "A"}`);
  await page.goto(tampered);
  await expect(page.getByTestId("verification-status")).toContainText("INVALID");
});
