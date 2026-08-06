import { expect, test, type Page } from "@playwright/test";
import { CHIEF_ADMIN_PASSWORD, RECOVERY_SHARES } from "../fixture-backend.ts";

const FIXTURE = `http://127.0.0.1:${process.env.ONELAYER_E2E_FIXTURE_PORT ?? "8199"}`;
const OPERATOR_PASSWORD = "operator-password-0123456789";

async function scenario(page: Page, body: Record<string, unknown>, reset = true): Promise<void> {
  const response = await page.request.post(`${FIXTURE}/__fixture/scenario`, { data: reset ? { resetBackups: true, ...body } : body });
  expect(response.ok()).toBeTruthy();
}

async function signIn(page: Page, user: "operator" | "chief_admin" = "operator"): Promise<void> {
  await page.goto("/admin");
  await page.getByTestId("login-username").selectOption(user);
  await page.getByTestId("login-password").fill(user === "operator" ? OPERATOR_PASSWORD : CHIEF_ADMIN_PASSWORD);
  await page.getByTestId("login-submit").click();
  await expect(page.getByTestId("session-role")).toHaveText(user);
}

test.beforeEach(async ({ page }) => {
  await scenario(page, {});
});

test("bootstraps five centers, adds a sixth, and replicates one immutable snapshot", async ({ page }) => {
  await signIn(page);
  await page.goto("/admin/backups");
  await expect(page.getByTestId("backup-center-count")).toHaveText("5");

  await page.getByTestId("backup-center-name").fill("Local BackupCenter 06");
  await page.getByTestId("create-backup-center").click();
  await expect(page.getByTestId("backup-center-count")).toHaveText("6");

  await page.getByTestId("refresh-backups").click();
  await expect(page.getByTestId("snapshot-count")).toHaveText("1");
  await expect(page.locator("[data-testid^='replica-']")).toHaveCount(6);
  await expect(page.locator("[data-testid^='replica-']").first()).toContainText("COPIED");
  await expect(page.locator("[data-testid^='folders-BACKUPCENTER-6']")).toContainText("Snapshot");
});

test("shows partial success and retries the same pending replica", async ({ page }) => {
  await scenario(page, { unavailableCenterIds: ["BACKUPCENTER-2"] });
  await signIn(page);
  await page.goto("/admin/backups");
  await page.getByTestId("refresh-backups").click();
  await expect(page.locator("[data-testid^='replica-BACKUPCENTER-2-']")).toContainText("PENDING RETRY");
  await expect(page.locator("[data-testid^='replica-BACKUPCENTER-1-']")).toContainText("COPIED");

  await scenario(page, { unavailableCenterIds: [] }, false);
  await page.locator("[data-testid^='retry-BACKUPCENTER-2-']").click();
  await expect(page.locator("[data-testid^='replica-BACKUPCENTER-2-']")).toContainText("COPIED");
});

test("retention keeps twelve folders and preserves the finalized snapshot", async ({ page }) => {
  await signIn(page);
  await page.goto("/admin/backups");
  for (let index = 0; index < 13; index += 1) {
    await page.getByTestId("refresh-backups").click();
  }
  await expect(page.getByTestId("snapshot-count")).toHaveText("13");
  await expect(page.locator("[data-testid^='folders-BACKUPCENTER-1']").locator(".ol-subcard")).toHaveCount(12);
  await expect(page.locator("[data-testid^='folders-BACKUPCENTER-1']")).toContainText("FINALIZED");
});

test("chief_admin can view centers but cannot mutate or delete backups", async ({ page }) => {
  await signIn(page, "chief_admin");
  await page.goto("/admin/backups");
  await expect(page.getByTestId("backup-center-count")).toHaveText("5");
  await expect(page.getByTestId("refresh-backups")).toBeDisabled();
  await expect(page.getByTestId("create-backup-center")).toBeDisabled();

  const csrf = await page.evaluate(async () => (await (await fetch("/api/admin/session")).json()).csrfToken as string);
  const status = await page.evaluate(async (token) => (await fetch("/api/admin/snapshots", {
    method: "DELETE",
    headers: { "x-onelayer-csrf": token },
  })).status, csrf);
  expect(status).toBe(403);
});

test("recovery rejects two shares before creating an approval operation", async ({ page }) => {
  await signIn(page);
  await page.goto("/admin/backups");
  await page.getByTestId("refresh-backups").click();
  await page.getByTestId("recovery-share-1").fill(RECOVERY_SHARES[0]);
  await page.getByTestId("recovery-share-2").fill(RECOVERY_SHARES[1]);
  await page.getByTestId("prepare-recovery").click();
  await expect(page.getByTestId("backup-error")).toHaveText("RECOVERY_SHARES_INSUFFICIENT");
  await expect(page.getByTestId("recovery-operation")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText(RECOVERY_SHARES[0]);
});

test("ciphertext and root failures stop recovery before Restore Approval", async ({ page }) => {
  await scenario(page, { corruptCiphertext: true });
  await signIn(page);
  await page.goto("/admin/backups");
  await page.getByTestId("refresh-backups").click();
  for (let index = 0; index < 3; index += 1) {
    await page.getByTestId(`recovery-share-${index + 1}`).fill(RECOVERY_SHARES[index]);
  }
  await page.getByTestId("prepare-recovery").click();
  await expect(page.getByTestId("backup-error")).toHaveText("CIPHERTEXT_HASH_MISMATCH");

  await scenario(page, { rootMismatch: true });
  await page.getByTestId("refresh-backups").click();
  for (let index = 0; index < 3; index += 1) {
    await page.getByTestId(`recovery-share-${index + 1}`).fill(RECOVERY_SHARES[index]);
  }
  await page.getByTestId("prepare-recovery").click();
  await expect(page.getByTestId("backup-error")).toHaveText("MERKLE_ROOT_MISMATCH");
});

test("anchor, incident and decryption failures stay fail-closed", async ({ page }) => {
  await signIn(page);
  await page.goto("/admin/backups");
  for (const [failure, expected] of [
    [{ anchorUnavailable: true }, "RECOVERY_ANCHOR_UNAVAILABLE"],
    [{ openIncident: true }, "RECOVERY_ANCHOR_UNAVAILABLE"],
    [{ plaintextHashMismatch: true }, "PLAINTEXT_HASH_MISMATCH"],
    [{ decryptionFails: true }, "DECRYPTION_FAILED"],
  ] as const) {
    await scenario(page, failure);
    await page.getByTestId("refresh-backups").click();
    for (let index = 0; index < 3; index += 1) {
      await page.getByTestId(`recovery-share-${index + 1}`).fill(RECOVERY_SHARES[index]);
    }
    await page.getByTestId("prepare-recovery").click();
    await expect(page.getByTestId("backup-error")).toHaveText(expected);
  }
});

test("three shares wait for chief approval, preserve the binding, and restore the full state", async ({ page }) => {
  await signIn(page);
  await page.goto("/admin/backups");
  await page.getByTestId("refresh-backups").click();
  for (let index = 0; index < 3; index += 1) {
    await page.getByTestId(`recovery-share-${index + 1}`).fill(RECOVERY_SHARES[index]);
  }
  await page.getByTestId("prepare-recovery").click();
  await expect(page.getByTestId("recovery-state")).toContainText("AWAITING RESTORE APPROVAL");
  await expect(page.getByTestId("recovery-anchor-root")).toHaveText("aa".repeat(32));
  const operationId = await page.getByTestId("recovery-operation-id").textContent();
  expect(operationId).toMatch(/^[0-9a-f-]{36}$/);

  const operatorApprovalStatus = await page.evaluate(async ({ id }) => {
    const session = await (await fetch("/api/admin/session")).json() as { csrfToken: string };
    return (await fetch(`/api/admin/recovery/operations/${id}/approve`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-onelayer-csrf": session.csrfToken },
      body: JSON.stringify({ snapshotId: "wrong", merkleRoot: "00".repeat(32), target: "local-demo-other" }),
    })).status;
  }, { id: operationId });
  expect(operatorApprovalStatus).toBe(403);

  await page.getByTestId("logout").click();
  await signIn(page, "chief_admin");
  await page.goto("/admin/backups");
  await expect(page.getByTestId("recovery-state")).toContainText("AWAITING RESTORE APPROVAL");
  await page.getByTestId("approve-restore").click();
  await expect(page.getByTestId("recovery-state")).toContainText("APPROVED · RESTORE READY");

  await page.getByTestId("logout").click();
  await signIn(page);
  await page.goto("/admin/backups");
  await expect(page.getByTestId("recovery-state")).toContainText("APPROVED · RESTORE READY");
  await page.getByTestId("restore-recovery").click();
  await expect(page.getByTestId("recovery-state")).toContainText("RESTORED");
  await expect(page.getByTestId("recovery-plaintext-cleared")).toContainText("plaintext cleared");
  await expect(page.locator("body")).not.toContainText(RECOVERY_SHARES[0]);
});
