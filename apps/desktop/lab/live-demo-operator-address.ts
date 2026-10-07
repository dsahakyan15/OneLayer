// Desktop-side public-address helper for the live-demo launcher (B2).
//
// Prints the operator's **public** Solana address from the A1 persistent key
// store. Key bytes never leave `live-demo-key-store.ts`: this helper only ever
// emits the address, the key file path and whether the file was created.
//
//   node --experimental-transform-types --disable-warning=ExperimentalWarning \
//     apps/desktop/lab/live-demo-operator-address.ts [--key-file FILE] [--ensure]
//
// stdout (success, exactly one line):
//   {"address":"<base58>","path":"<absolute key file>","created":<bool>}
// stderr (failure, exactly one line): {"error":{"code":"<CODE>"}}
// exit codes: 0 ok · 2 usage/refusal · 3 key-file problem.
//
// `--ensure` initializes the key store idempotently (no overwrite: an existing
// file always wins) and is meant for seeding/tests; without it the lookup is
// read-only and a missing key is an error, so the launcher never silently
// invents a signing identity. No key contents are ever printed or logged.
import { KeyStoreError, defaultKeyFile, ensureKeyPair, loadSigningKey } from "../../demo-api/scripts/live-demo-key-store.ts";

const USAGE =
  "usage: live-demo-operator-address.ts [--key-file FILE] [--ensure]\n";

class UsageRefusal extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

function parseArgs(argv: readonly string[]): { keyFile: string | undefined; ensure: boolean } {
  let keyFile: string | undefined;
  let ensure = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "-h" || argument === "--help") throw new UsageRefusal("USAGE");
    if (argument === "--ensure") {
      ensure = true;
      continue;
    }
    if (argument === "--key-file") {
      const value = argv[index + 1];
      if (value === undefined || value === "") throw new UsageRefusal("REQUEST_INVALID");
      if (keyFile !== undefined) throw new UsageRefusal("REQUEST_INVALID");
      keyFile = value;
      index += 1;
      continue;
    }
    throw new UsageRefusal("REQUEST_INVALID");
  }
  return { keyFile, ensure };
}

async function main(): Promise<void> {
  const { keyFile, ensure } = parseArgs(process.argv.slice(2));
  if (ensure) {
    const result = await ensureKeyPair(keyFile === undefined ? {} : { keyFile });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  const target = keyFile ?? defaultKeyFile();
  const loaded = await loadSigningKey(target);
  // Only the public address and the path leave this process.
  process.stdout.write(`${JSON.stringify({ address: String(loaded.address), path: target, created: false })}\n`);
}

const entry = process.argv[1];
if (entry !== undefined) {
  main().catch((error: unknown) => {
    const code =
      error instanceof UsageRefusal
        ? error.code
        : error instanceof KeyStoreError
          ? error.code
          : "ADDRESS_INTERNAL_ERROR";
    process.stderr.write(`${JSON.stringify({ error: { code } })}\n`);
    // Usage/refusal → 2, key-file problems → 3 (same contract as live-demo-sign.ts).
    process.exit(error instanceof KeyStoreError ? 3 : error instanceof UsageRefusal ? 2 : 1);
  });
}
