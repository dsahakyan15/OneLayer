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
  await page.getByTestId("login-username").fill("operator");
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

/** A complete v2 envelope; tests override only the fields they are about. */
function v2Envelope(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    resultVersion: 2,
    status: "UNKNOWN",
    code: "LIFECYCLE_UNAUTHENTICATED",
    checkedAt: "2026-10-01T12:00:00.000Z",
    certificateId: "0".repeat(31) + "1",
    recordVersion: "1",
    batchSequence: "1",
    proofs: { status: "VERIFIED", anchorSlot: "412346000" },
    registry: { registryId: "gov.registry.land", status: "CHECKED" },
    incidents: { status: "CHECKED", indexedThroughSlot: "412346040", finalizedHeadSlot: "412346050", lagSlots: "10" },
    lifecycle: {
      status: "UNAUTHENTICATED",
      code: "LIFECYCLE_UNAUTHENTICATED",
      reported: { certificateStatus: "ACTIVE", currentRecordVersion: "1" },
    },
    warnings: ["Current suitability is not proven. Lifecycle reports are advisory until an authenticated complete source is implemented."],
    disclosureMode: "FULL_RECORD",
    disclosedFields: { parcelAddress: "1 Example Street, Yerevan", cadastralNumber: "01-001-0001-0001" },
    ...overrides,
  };
}

/** The producer's INVALID envelope: every optional v2 field is absent here. */
const MINIMAL_INVALID_V2: Record<string, unknown> = {
  resultVersion: 2,
  status: "INVALID",
  code: "FIELD_PROOF_INVALID",
  checkedAt: "2026-10-01T12:00:00.000Z",
  certificateId: "0".repeat(31) + "1",
  recordVersion: "1",
  batchSequence: "1",
  proofs: { status: "NOT_ESTABLISHED" },
  registry: { registryId: "gov.registry.land", status: "NOT_ESTABLISHED" },
  incidents: { status: "NOT_CHECKED" },
  lifecycle: { status: "UNKNOWN", code: "LIFECYCLE_UNAVAILABLE" },
  warnings: [],
};

test.beforeEach(async ({ page }) => {
  await scenario(page, {});
});

test("a scanned certificate renders the v2 envelope without claiming current status", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await page.goto(qrUrl);
  const result = page.getByTestId("verification-result");
  await expect(result).toHaveAttribute("data-result-version", "2");
  await expect(result).toHaveAttribute("data-status", "UNKNOWN");
  await expect(result).toHaveAttribute("data-verdict", "unproven");
  const badge = page.getByTestId("verification-status");
  await expect(badge).toContainText("UNKNOWN");
  // "Proofs verified" is about the anchored package; the overall verdict must not read as success.
  await expect(badge).not.toHaveAttribute("data-tone", "ok");
  await expect(page.getByTestId("proofs-status")).toContainText("PROOFS VERIFIED");
  await expect(page.getByTestId("registry-status")).toContainText("REGISTRY CHECKED");
  await expect(page.getByTestId("incident-index-status")).toContainText("INDEX CHECKED");
  await expect(page.getByTestId("lifecycle-status")).toContainText("ADVISORY");
  await expect(page.getByTestId("verification-checked-at")).toHaveAttribute("datetime", "2026-10-01T12:00:00.000Z");
  await expect(page.getByTestId("disclosed-fields")).toBeVisible();
  // The wire contract has no CURRENT value, and no label may invent one.
  await expect(result).not.toContainText("CURRENT");
});

test("a REVOKED lifecycle report stays advisory and never becomes current", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, {
    verificationV2: v2Envelope({
      status: "REVOKED",
      lifecycle: { status: "UNAUTHENTICATED", code: "LIFECYCLE_UNAUTHENTICATED", reported: { certificateStatus: "REVOKED", currentRecordVersion: "1" } },
    }),
  });
  await page.goto(qrUrl);
  const result = page.getByTestId("verification-result");
  await expect(result).toHaveAttribute("data-status", "REVOKED");
  await expect(result).toHaveAttribute("data-verdict", "advisory");
  const badge = page.getByTestId("verification-status");
  await expect(badge).toContainText("REVOKED");
  await expect(badge).not.toHaveAttribute("data-tone", "ok");
  await expect(page.getByTestId("proofs-status")).toContainText("PROOFS VERIFIED");
  await expect(page.getByTestId("lifecycle-status")).toContainText("ADVISORY");
  await expect(page.getByTestId("lifecycle-explanation")).toContainText("unauthenticated source");
  await expect(page.getByTestId("lifecycle-reported")).toContainText("REVOKED");
});

test("a newer record version renders HISTORICAL advisory, not a current record", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, {
    verificationV2: v2Envelope({
      status: "HISTORICAL",
      lifecycle: { status: "UNAUTHENTICATED", code: "LIFECYCLE_UNAUTHENTICATED", reported: { certificateStatus: "ACTIVE", currentRecordVersion: "3" } },
    }),
  });
  await page.goto(qrUrl);
  const result = page.getByTestId("verification-result");
  await expect(result).toHaveAttribute("data-verdict", "advisory");
  await expect(page.getByTestId("verification-status")).toContainText("HISTORICAL");
  await expect(page.getByTestId("lifecycle-explanation")).toContainText("advisory");
  await expect(page.getByTestId("lifecycle-reported")).toContainText("3");
  await expect(result).not.toContainText("CURRENT");
});

test("a blocking incident renders DISPUTED and blocks verification", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, { verificationV2: v2Envelope({ status: "DISPUTED" }) });
  await page.goto(qrUrl);
  const result = page.getByTestId("verification-result");
  await expect(result).toHaveAttribute("data-status", "DISPUTED");
  await expect(result).toHaveAttribute("data-verdict", "blocking");
  await expect(page.getByTestId("verification-status")).toContainText("DISPUTED");
  await expect(page.getByTestId("verification-explanation")).toContainText("blocked");
});

test("a stale incident index is reported and never turns the verdict green", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, {
    verificationV2: v2Envelope({
      incidents: { status: "STALE", indexedThroughSlot: "412000000", finalizedHeadSlot: "412346050", lagSlots: "346050" },
    }),
  });
  await page.goto(qrUrl);
  await expect(page.getByTestId("incident-index-status")).toContainText("INDEX STALE");
  const badge = page.getByTestId("verification-status");
  await expect(badge).toContainText("UNKNOWN");
  await expect(badge).not.toHaveAttribute("data-tone", "ok");
});

test("an unknown result version fails closed instead of being read as v2", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, {
    verificationV2: v2Envelope({
      resultVersion: 3,
      status: "VERIFIED",
      disclosureMode: "FULL_RECORD",
      disclosedFields: { parcelAddress: "value from an unknown version" },
    }),
  });
  await page.goto(qrUrl);
  const result = page.getByTestId("verification-result");
  await expect(result).toHaveAttribute("data-result-version", "discarded");
  await expect(result).toHaveAttribute("data-status", "UNINTERPRETABLE");
  await expect(result).toHaveAttribute("data-verdict", "blocking");
  await expect(page.getByTestId("verification-status")).toContainText("UNINTERPRETABLE RESULT");
  await expect(page.getByTestId("verification-explanation")).toContainText("result version 3");
  await expect(page.getByTestId("proofs-status")).toHaveCount(0);
  await expect(page.getByTestId("disclosed-fields")).toHaveCount(0);
  await expect(result).not.toContainText("value from an unknown version");
  await expect(result).not.toContainText("CURRENT");
});

test("a verdict or proof state this build does not know is discarded, not rendered as proven", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, {
    verificationV2: v2Envelope({
      status: "CURRENT",
      disclosureMode: "FULL_RECORD",
      disclosedFields: { parcelAddress: "value under an unknown verdict" },
    }),
  });
  await page.goto(qrUrl);
  const result = page.getByTestId("verification-result");
  await expect(result).toHaveAttribute("data-result-version", "discarded");
  await expect(page.getByTestId("verification-status")).toContainText("UNINTERPRETABLE RESULT");
  await expect(page.getByTestId("proofs-status")).toHaveCount(0);
  await expect(page.getByTestId("disclosed-fields")).toHaveCount(0);
  await expect(result).not.toContainText("value under an unknown verdict");
  await expect(result).not.toContainText("CURRENT");

  // The proof state is validated as strictly as the verdict.
  await scenario(page, {
    verificationV2: v2Envelope({
      proofs: { status: "PROBABLY_FINE", anchorSlot: "412346000" },
      disclosureMode: "FULL_RECORD",
      disclosedFields: { parcelAddress: "value under an unknown proof state" },
    }),
  });
  await page.reload();
  await expect(result).toHaveAttribute("data-result-version", "discarded");
  await expect(page.getByTestId("proofs-status")).toHaveCount(0);
  await expect(page.getByTestId("disclosed-fields")).toHaveCount(0);
  await expect(result).not.toContainText("value under an unknown proof state");
});

test("prototype names, inconsistent pairs and legacy-shaped answers are discarded", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  const result = page.getByTestId("verification-result");

  // A prototype property name is not a known verdict, even though the lookup
  // would find Object.prototype.constructor or Object.prototype.toString.
  await scenario(page, {
    verificationV2: v2Envelope({
      status: "constructor",
      disclosureMode: "FULL_RECORD",
      disclosedFields: { parcelAddress: "value under a prototype name" },
    }),
  });
  await page.goto(qrUrl);
  await expect(result).toHaveAttribute("data-result-version", "discarded");
  await expect(result).toHaveAttribute("data-status", "UNINTERPRETABLE");
  await expect(page.getByTestId("verification-status")).toContainText("UNINTERPRETABLE RESULT");
  await expect(page.getByTestId("proofs-status")).toHaveCount(0);
  await expect(page.getByTestId("disclosed-fields")).toHaveCount(0);
  await expect(result).not.toContainText("value under a prototype name");

  await scenario(page, { verificationV2: v2Envelope({ status: "toString" }) });
  await page.reload();
  await expect(result).toHaveAttribute("data-result-version", "discarded");

  // JSON values must never be coerced into map keys. A singleton array can
  // stringify to a known verdict, while this object cannot coerce at all.
  for (const status of [["UNKNOWN"], { toString: null }, null, 7]) {
    await scenario(page, { verificationV2: v2Envelope({ status }) });
    await page.reload();
    await expect(result).toHaveAttribute("data-result-version", "discarded");
    await expect(page.getByTestId("proofs-status")).toHaveCount(0);
    await expect(page.getByTestId("disclosed-fields")).toHaveCount(0);
  }

  // The producer pair rule: INVALID establishes no proof, every other verdict
  // carries VERIFIED. A mismatched pair is refused before any badge appears.
  await scenario(page, {
    verificationV2: v2Envelope({
      status: "INVALID",
      code: "FIELD_PROOF_INVALID",
      proofs: { status: "VERIFIED" },
      disclosureMode: "FULL_RECORD",
      disclosedFields: { parcelAddress: "value under a mismatched pair" },
    }),
  });
  await page.reload();
  await expect(result).toHaveAttribute("data-result-version", "discarded");
  await expect(page.getByTestId("proofs-status")).toHaveCount(0);
  await expect(page.getByTestId("disclosed-fields")).toHaveCount(0);
  await expect(result).not.toContainText("value under a mismatched pair");

  await scenario(page, { verificationV2: v2Envelope({ status: "UNKNOWN", proofs: { status: "NOT_ESTABLISHED" } }) });
  await page.reload();
  await expect(result).toHaveAttribute("data-result-version", "discarded");
  await expect(page.getByTestId("verification-status")).toContainText("UNINTERPRETABLE RESULT");

  // A legacy-shaped answer (no resultVersion: 2) is never read with v2 assumptions.
  await scenario(page, {
    verificationV2: {
      status: "VERIFIED",
      certificateId: "0".repeat(31) + "1",
      batchSequence: "1",
      warnings: [],
      disclosureMode: "FULL_RECORD",
      disclosedFields: { parcelAddress: "legacy value" },
    },
  });
  await page.reload();
  await expect(result).toHaveAttribute("data-result-version", "discarded");
  await expect(page.getByTestId("proofs-status")).toHaveCount(0);
  await expect(page.getByTestId("disclosed-fields")).toHaveCount(0);
  await expect(result).not.toContainText("legacy value");
});

test("an INVALID body never renders disclosed values as proven", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, {
    verificationV2: v2Envelope({
      status: "INVALID",
      code: "FIELD_PROOF_INVALID",
      proofs: { status: "NOT_ESTABLISHED" },
      registry: { registryId: "gov.registry.land", status: "NOT_ESTABLISHED" },
      incidents: { status: "NOT_CHECKED" },
      lifecycle: { status: "UNKNOWN", code: "LIFECYCLE_UNAVAILABLE" },
      disclosureMode: "FULL_RECORD",
      disclosedFields: { parcelAddress: "value that was never proven" },
    }),
  });
  await page.goto(qrUrl);
  const result = page.getByTestId("verification-result");
  await expect(result).toHaveAttribute("data-status", "INVALID");
  await expect(result).toHaveAttribute("data-verdict", "blocking");
  await expect(page.getByTestId("verification-code")).toHaveText("FIELD_PROOF_INVALID");
  await expect(page.getByTestId("proofs-status")).toContainText("PROOFS NOT ESTABLISHED");
  await expect(page.getByTestId("disclosed-fields")).toHaveCount(0);
  await expect(result).not.toContainText("value that was never proven");
});

test("an unavailable v2 verifier stays an error and never requests the legacy route", async ({ page }) => {
  const verifyCalls: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/verify/")) verifyCalls.push(url.pathname);
  });
  const qrUrl = await issueCertificate(page);
  await scenario(page, { verifyV2Unavailable: true });
  await page.goto(qrUrl);
  const result = page.getByTestId("verification-result");
  await expect(result).toHaveAttribute("data-result-version", "local");
  await expect(page.getByTestId("verification-status")).toContainText("INVALID");
  await expect(page.getByTestId("verification-code")).toHaveText("NOT_FOUND");
  // A v2 failure is an error: the legacy route exists for compatibility but is
  // never fetched as a fallback.
  expect(verifyCalls).toContain("/api/verify/v2/verify");
  expect(verifyCalls).not.toContain("/api/verify/v1/verify");
  await expect(page.getByTestId("proofs-status")).toHaveCount(0);
  await expect(page.getByTestId("disclosed-fields")).toHaveCount(0);
});

test("a QR from a paused registry is refused", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, { registryPaused: true });
  await page.goto(qrUrl);
  const result = page.getByTestId("verification-result");
  // The paused registry refuses the package before any verifier call, so the
  // browser reports a local failure with nothing attributed to a verifier.
  await expect(result).toHaveAttribute("data-result-version", "local");
  await expect(page.getByTestId("verification-status")).toContainText("INVALID");
  await expect(page.getByTestId("verification-code")).toHaveText("REGISTRY_PAUSED");
});

test("manual input reaches the same result as the QR link", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await page.goto("/verify");
  await page.getByTestId("mode-manual").click();
  await page.getByTestId("manual-input").fill(qrUrl);
  await page.getByTestId("manual-submit").click();
  await expect(page.getByTestId("verification-result")).toHaveAttribute("data-result-version", "2");
  await expect(page.getByTestId("verification-status")).toContainText("UNKNOWN");
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
  await expect(page.getByTestId("verification-code")).toHaveText("CERT_SIGNATURE_INVALID");
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
  await expect(badge).toContainText("UNKNOWN");
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

test("a v2 answer with no body is discarded instead of crashing the page", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  // An empty 200 body parses to null; a literal null body arrives as null too.
  let answer = "";
  await page.route("**/api/verify/v2/verify", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: answer }));
  for (const candidate of ["", "null"]) {
    answer = candidate;
    await page.goto("/verify");
    await page.getByTestId("mode-manual").click();
    await page.getByTestId("manual-input").fill("A".repeat(40));
    await page.getByTestId("manual-submit").click();
    const result = page.getByTestId("verification-result");
    await expect(result, `body ${JSON.stringify(candidate)}`).toHaveAttribute("data-result-version", "discarded");
    await expect(result).toHaveAttribute("data-status", "UNINTERPRETABLE");
    await expect(result).toHaveAttribute("data-verdict", "blocking");
    await expect(page.getByTestId("verification-status")).toContainText("UNINTERPRETABLE RESULT");
    await expect(page.getByTestId("proofs-status")).toHaveCount(0);
    await expect(page.getByTestId("disclosed-fields")).toHaveCount(0);
    await expect(page.getByTestId("verification-code")).toHaveCount(0);
  }
  expect(errors).toEqual([]);
});

test("a rendered v2 field holding an array or an object is discarded, never coerced", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  const result = page.getByTestId("verification-result");
  const cases: Array<{ why: string; envelope: Record<string, unknown>; absent?: string }> = [
    { why: "an array certificate id must not be joined into a value",
      envelope: v2Envelope({ certificateId: ["forged", "-certificate"] }), absent: "forged-certificate" },
    { why: "an object record version must not be rendered",
      envelope: v2Envelope({ recordVersion: {} }) },
    { why: "a structured warning must not be rendered",
      envelope: v2Envelope({ warnings: [{ forged: true }] }) },
    { why: "wire integer disclosures must be strings rather than numbers",
      envelope: v2Envelope({ disclosedFields: { areaSquareMeters: 120 } }) },
    { why: "an array anchor slot is not a decimal string",
      envelope: v2Envelope({ proofs: { status: "VERIFIED", anchorSlot: ["412346000"] } }) },
    { why: "a numeric lag is not a decimal string",
      envelope: v2Envelope({ incidents: { status: "CHECKED", lagSlots: 10 } }) },
    { why: "a registry status outside the contract is unknown",
      envelope: v2Envelope({ registry: { registryId: "gov.registry.land", status: "PROBABLY_FINE" } }) },
  ];
  for (const item of cases) {
    await scenario(page, { verificationV2: item.envelope });
    await page.goto(qrUrl);
    await expect(result, item.why).toHaveAttribute("data-result-version", "discarded");
    await expect(page.getByTestId("proofs-status"), item.why).toHaveCount(0);
    await expect(page.getByTestId("disclosed-fields"), item.why).toHaveCount(0);
    if (item.absent !== undefined) await expect(result, item.why).not.toContainText(item.absent);
  }
  expect(errors).toEqual([]);
});

test("an inconsistent lifecycle projection or an unknown disclosure mode is refused whole", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  const result = page.getByTestId("verification-result");
  const cases: Array<{ why: string; envelope: Record<string, unknown>; absent: string }> = [
    { why: "reported values belong to the advisory status only",
      envelope: v2Envelope({ lifecycle: { status: "UNKNOWN", code: "LIFECYCLE_UNAVAILABLE", reported: { certificateStatus: "REVOKED", currentRecordVersion: "99" } } }),
      absent: "REVOKED" },
    { why: "an unknown lifecycle status is not a label",
      envelope: v2Envelope({ lifecycle: { status: "SOMETHING_NEW", code: "LIFECYCLE_UNAVAILABLE" } }),
      absent: "SOMETHING_NEW" },
    { why: "an unknown disclosure mode must not claim a full record",
      envelope: v2Envelope({ disclosureMode: "PROOF_ONLY", disclosedFields: { parcelAddress: "forged-disclosure" } }),
      absent: "forged-disclosure" },
    { why: "disclosed values without a declared mode cannot be labelled",
      envelope: v2Envelope({ disclosureMode: undefined, disclosedFields: { parcelAddress: "undeclared-mode" } }),
      absent: "undeclared-mode" },
    { why: "an array field value must not be concatenated into evidence",
      envelope: v2Envelope({ disclosureMode: "FULL_RECORD", disclosedFields: { parcelAddress: ["forged", "-field"] } }),
      absent: "forged-field" },
  ];
  for (const item of cases) {
    await scenario(page, { verificationV2: item.envelope });
    await page.goto(qrUrl);
    await expect(result, item.why).toHaveAttribute("data-result-version", "discarded");
    await expect(page.getByTestId("lifecycle-reported"), item.why).toHaveCount(0);
    await expect(page.getByTestId("disclosed-fields"), item.why).toHaveCount(0);
    await expect(result, item.why).not.toContainText("Full record");
    await expect(result, item.why).not.toContainText(item.absent);
  }
});

test("an INVALID answer without the optional fields still renders and discloses nothing", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, { verificationV2: MINIMAL_INVALID_V2 });
  await page.goto(qrUrl);
  const result = page.getByTestId("verification-result");
  await expect(result).toHaveAttribute("data-result-version", "2");
  await expect(result).toHaveAttribute("data-status", "INVALID");
  await expect(result).toHaveAttribute("data-verdict", "blocking");
  await expect(page.getByTestId("proofs-status")).toContainText("PROOFS NOT ESTABLISHED");
  await expect(page.getByTestId("registry-status")).toContainText("REGISTRY NOT ESTABLISHED");
  await expect(page.getByTestId("incident-index-status")).toContainText("INDEX NOT CHECKED");
  await expect(page.getByTestId("lifecycle-status")).toContainText("LIFECYCLE UNKNOWN");
  await expect(page.getByTestId("lifecycle-reported")).toHaveCount(0);
  await expect(page.getByTestId("disclosed-fields")).toHaveCount(0);
});


test("selective disclosure preserves boolean, null and integer-string values without a full-record claim", async ({ page }) => {
  const qrUrl = await issueCertificate(page);
  await scenario(page, { verificationV2: v2Envelope({
    disclosureMode: "SELECTIVE_FIELDS",
    disclosedFields: { notarized: true, expired: false, nested: null, areaSquareMeters: "120" },
  }) });
  await page.goto(qrUrl);
  await expect(page.getByTestId("verification-result")).toHaveAttribute("data-result-version", "2");
  await expect(page.getByTestId("disclosure-mode")).toContainText("Selective disclosure");
  await expect(page.getByTestId("disclosure-mode")).not.toContainText("Full record");
  const fields = page.getByTestId("disclosed-fields");
  await expect(fields.locator("dd")).toHaveText(["true", "false", "null", "120"]);
  await expect(fields.locator("dt")).toHaveText(["notarized", "expired", "nested", "areaSquareMeters"]);
});
