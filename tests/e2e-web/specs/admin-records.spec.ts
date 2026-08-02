// Record entry, import and selective disclosure (OL-C-36…OL-C-40).
//
// The field set comes from the certificate the user supplies, so these
// scenarios exercise the schema-driven form, the JSON/CSV import report and the
// disclosure choice made before issuing.
import { expect, test, type Page } from "@playwright/test";
import { mockWalletScript } from "../mock-wallet.ts";

const OPERATOR_PASSWORD = "operator-password-0123456789";

async function signIn(page: Page): Promise<void> {
  await page.goto("/admin");
  await page.getByTestId("login-username").selectOption("operator");
  await page.getByTestId("login-password").fill(OPERATOR_PASSWORD);
  await page.getByTestId("login-submit").click();
  await expect(page.getByTestId("session-role")).toHaveText("operator");
}

test("the wizard is rendered from the schema the API serves", async ({ page }) => {
  await signIn(page);
  await page.goto("/admin/records");

  await expect(page.getByTestId("field-status")).toBeVisible();
  await expect(page.getByTestId("field-cadastralNumber")).toBeVisible();
  await expect(page.getByTestId("field-areaSquareMeters")).toBeVisible();

  await page.getByTestId("record-id").fill("SYNTHETIC-31");
  await page.getByTestId("field-status").selectOption("ACTIVE");
  await page.getByTestId("field-cadastralNumber").fill("01-004-0999-001");
  await page.getByTestId("field-areaSquareMeters").fill("980.00");
  await page.getByTestId("record-submit").click();

  await expect(page.getByTestId("record-detail")).toBeVisible();
  await expect(page.getByTestId("detail-fields")).toContainText("cadastralNumber");
  await expect(page.getByTestId("detail-fields")).toContainText("980.00");
  await expect(page.getByTestId("detail-field-root")).toHaveText(/^[0-9a-f]{64}$/);
});

test("a dry run reports rejected rows and writes nothing", async ({ page }) => {
  await signIn(page);
  await page.goto("/admin/records");
  const rows = page.getByTestId("records-table").locator("tr");
  await expect(rows.first()).toBeVisible();
  const before = await rows.count();

  await page.getByTestId("import-format-csv").click();
  await page.getByTestId("import-content").fill([
    "internalRecordId,status,cadastralNumber,areaSquareMeters",
    "SYNTHETIC-41,ACTIVE,01-004-0999-041,100.00",
    // Second row carries a decimal with the wrong scale: "0.1" and "0.10" are
    // different commitments, so the row must be rejected rather than rounded.
    "SYNTHETIC-42,ACTIVE,01-004-0999-042,100.5",
  ].join("\n"));
  await page.getByTestId("import-dry-run").click();

  await expect(page.getByTestId("import-accepted")).toHaveText("1");
  await expect(page.getByTestId("import-rejected")).toHaveText("1");
  await expect(page.getByTestId("import-rejections")).toContainText("FIELD_DECIMAL_INVALID");
  await expect(rows).toHaveCount(before);
});

test("a path outside the schema is rejected, not dropped", async ({ page }) => {
  await signIn(page);
  await page.goto("/admin/records");

  await page.getByTestId("import-content").fill(JSON.stringify({
    internalRecordId: "SYNTHETIC-43",
    fields: { status: "ACTIVE", cadastralNumber: "01-004-0999-043", ownerFullName: "Someone" },
  }));
  await page.getByTestId("import-dry-run").click();

  await expect(page.getByTestId("import-rejections")).toContainText("CANONICALIZATION_FAILED");
  await expect(page.getByTestId("import-rejections")).toContainText("ownerFullName");
});

test("an imported certificate reaches the canonical preview", async ({ page }) => {
  await signIn(page);
  await page.goto("/admin/records");

  await page.getByTestId("import-content").fill(JSON.stringify({
    internalRecordId: "SYNTHETIC-44",
    fields: { status: "ACTIVE", cadastralNumber: "01-004-0999-044" },
  }));
  await page.getByTestId("import-apply").click();

  await expect(page.getByTestId("import-accepted")).toHaveText("1");
  await expect(page.getByTestId("records-table")).toContainText("SYNTHETIC-44");
  await expect(page.getByTestId("preview-records")).toContainText("SYNTHETIC-44");
});

test("a selective disclosure issues a package with the chosen paths only", async ({ page }) => {
  await page.addInitScript(mockWalletScript({}));
  await signIn(page);
  await page.goto("/admin/publish");

  await page.getByTestId("wallet-connect").click();
  await page.getByTestId("prepare-batch").click();
  await expect(page.getByTestId("transaction-state")).toContainText("SIMULATED");
  await page.getByTestId("sign-transaction").click();
  await page.getByTestId("poll-status").click();
  await expect(page.getByTestId("transaction-state")).toContainText("FINALIZED");

  await expect(page.getByTestId("disclosure-summary")).toContainText("FULL_RECORD");
  await page.getByTestId("disclose-cadastralNumber").uncheck();
  await expect(page.getByTestId("disclosure-summary")).toContainText("SELECTIVE_FIELDS");

  await page.getByTestId("issue-certificate").click();
  await expect(page.getByTestId("issued-certificate")).toBeVisible();

  await page.goto("/admin/certificates");
  await expect(page.getByTestId("certificates-table")).toContainText("SELECTIVE_FIELDS");
});
