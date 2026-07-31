import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";

test("restore root CLI emits one canonical SHA-256 root", () => {
  const rows = [
    { internalRecordId: "SYNTHETIC-1", recordVersion: "1", status: "ACTIVE", recordFieldKeyHex: "01".repeat(32) },
    { internalRecordId: "SYNTHETIC-2", recordVersion: "1", status: "ACTIVE", recordFieldKeyHex: "02".repeat(32) },
  ];
  const output = execFileSync("node", ["src/root-cli.ts"], {
    cwd: new URL("..", import.meta.url),
    input: JSON.stringify(rows),
    encoding: "utf8",
  }).trim();
  assert.match(output, /^[0-9a-f]{64}$/);
});
