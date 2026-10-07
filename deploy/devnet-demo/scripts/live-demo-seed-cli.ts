// CLI for the live-demo seed (B4): assessment, opt-in preparation and the
// explicit fallback certificate.
//
// Assessment is read-only and always available. Chain preparation runs only
// under `--prepare`, and the standalone fallback publish only under
// `--approve-fallback`; both are the explicit reviewed confirmations for the
// test signer actions. A missing governance authority fails the run honestly
// with `GOVERNANCE_KEY_UNAVAILABLE` before any chain mutation — nothing is
// substituted, no program is deployed, trust policy and keys are never
// rotated or overwritten, and an initialized registry is never mutated.
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import {
  RegistryRefusal,
  type ReadinessOptions,
} from "../../../apps/demo-api/scripts/live-demo-registry.ts";
import {
  loadSeedSigner,
  JsonRpcSeedChain,
  SeedRefusal,
  type SeedSigner,
} from "./live-demo-seed-kit.ts";
import {
  prepareDemoChain,
  type PrepareReport,
} from "./live-demo-seed-executor.ts";
import {
  runFallbackCertificate,
  type FallbackReport,
} from "./live-demo-seed-fallback.ts";

process.removeAllListeners("warning");
process.on("warning", () => undefined);

export interface SeedCliReport extends PrepareReport {
  fallback: FallbackReport | null;
  fallbackSkipped: string | null;
}

const USAGE = `Usage: live-demo-seed [options]

Idempotent devnet preparation for the live-demo launcher (B4). Prints one JSON
report. Readiness assessment is read-only. Chain preparation (registry init,
operator role, bounded rent/fee funding, ledger segment) runs only with
--prepare, and the standalone fallback certificate (real finalized publish,
selective disclosure status + areaSquareMeters) only with --approve-fallback.
An already initialized registry is never mutated, no program is ever deployed,
and a missing governance authority fails with GOVERNANCE_KEY_UNAVAILABLE
before any chain mutation instead of substituting a key.

Options:
  --rpc-url URL            Solana RPC endpoint (default: https://api.devnet.solana.com)
  --demo-api-url URL       loopback demo-api base URL (default: http://127.0.0.1:8090)
  --verifier-url URL       loopback verifier base URL (default: http://127.0.0.1:8080)
  --operator ADDRESS       operator address to assess (no key access)
  --key-file FILE          operator key file in the A1 persistent store
                           (unsafe paths are refused as request errors)
  --init-operator-key      idempotently create the persistent demo-operator key
  --day YYYYMMDD           ledger day override (UTC)
  --prepare                execute the preparation path (explicit opt-in)
  --approve-fallback       publish the fallback certificate (explicit opt-in;
                           requires a ready preparation and an operator key)
  --fallback-record ID     record id for the fallback certificate
                           (default: SYNTHETIC-1)
  --artifacts DIR          artifact root for fallback outputs
                           (default: ~/.local/state/onelayer-devnet-demo/seed)
  -h, --help               show this help

Output (success/failure): one JSON seed report on stdout
Output (refusal): {"error":{"code":"..."}} on stderr in addition
Exit codes: 0 ready or prepared, 2 refused request (REQUEST_INVALID),
3 refused environment or authority (LINK_REFUSED, RPC_UNREACHABLE,
CLUSTER_NOT_DEVNET, GOVERNANCE_KEY_UNAVAILABLE, OPERATOR_KEY_UNAVAILABLE,
KEYFILE_*, FUNDING_*, CREDENTIALS_UNAVAILABLE, SERVICE_*, ACCOUNT_*,
HTTP_BODY_TOO_LARGE, APPROVAL_REQUIRED), 4 report produced but not ready,
1 internal error.

Key material is read only through the accepted A1 key store and never printed;
the operator password is read only from the private runtime credential file.
`;

function exitCodeFor(error: unknown): number {
  if (error instanceof SeedRefusal || error instanceof RegistryRefusal) {
    return error.code === "REQUEST_INVALID" ? 2 : 3;
  }
  return 1;
}

function codeOf(error: unknown): string {
  if (error instanceof SeedRefusal || error instanceof RegistryRefusal) return error.code;
  return "SEED_INTERNAL_ERROR";
}

async function resolveSigner(
  explicitKeyFile: string | undefined,
  keyStore: ReadinessOptions["keyStore"],
): Promise<SeedSigner | null> {
  try {
    return await loadSeedSigner(explicitKeyFile, keyStore);
  } catch (error) {
    if (error instanceof SeedRefusal) {
      // An unsafe explicit key path is a request error (A2 contract); a
      // missing or invalid key file is simply "no signer" for the report.
      if (error.code === "KEYFILE_REJECTED" && explicitKeyFile !== undefined) {
        throw new SeedRefusal("REQUEST_INVALID");
      }
      return null;
    }
    throw error;
  }
}

export interface SeedCliOptions extends ReadinessOptions {
  prepare: boolean;
  approveFallback: boolean;
  fallbackRecord: string;
  artifactsDir: string | undefined;
}

export function parseArgs(args: readonly string[]): SeedCliOptions {
  const options: SeedCliOptions = {
    prepare: false,
    approveFallback: false,
    fallbackRecord: "SYNTHETIC-1",
    artifactsDir: undefined,
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    const take = (): string => {
      const value = args[index + 1];
      if (value === undefined || value === "") throw new SeedRefusal("REQUEST_INVALID");
      index += 1;
      return value;
    };
    if (argument === "--rpc-url") options.rpcUrl = take();
    else if (argument === "--demo-api-url") options.demoApiUrl = take();
    else if (argument === "--verifier-url") options.verifierUrl = take();
    else if (argument === "--operator") options.operator = take();
    else if (argument === "--key-file") options.keyFile = take();
    else if (argument === "--init-operator-key") options.initOperatorKey = true;
    else if (argument === "--day") {
      const value = take();
      if (!/^[0-9]{8}$/.test(value)) throw new SeedRefusal("REQUEST_INVALID");
      options.dayUtc = Number(value);
    } else if (argument === "--prepare") options.prepare = true;
    else if (argument === "--approve-fallback") options.approveFallback = true;
    else if (argument === "--fallback-record") {
      const value = take();
      if (!/^SYNTHETIC-[1-9][0-9]*$/.test(value)) throw new SeedRefusal("REQUEST_INVALID");
      options.fallbackRecord = value;
    } else if (argument === "--artifacts") options.artifactsDir = take();
    else throw new SeedRefusal("REQUEST_INVALID");
  }
  return options;
}

export async function runSeed(options: SeedCliOptions): Promise<{ report: SeedCliReport; exit: number }> {
  const signer = await resolveSigner(options.keyFile, options.keyStore);
  const chain = new JsonRpcSeedChain(options.rpcUrl ?? "https://api.devnet.solana.com");
  const { prepare, approveFallback, fallbackRecord, artifactsDir, ...readiness } = options;
  const prepared = await prepareDemoChain({ ...readiness, prepare, chain, signer });
  let fallback: FallbackReport | null = null;
  let fallbackSkipped: string | null = null;
  let refusal = prepared.refusal;
  if (approveFallback) {
    if (refusal !== null) {
      fallbackSkipped = `preparation refused (${refusal.code}); no fallback certificate was published`;
    } else if (!prepared.ok) {
      fallbackSkipped = "preparation is not ready; no fallback certificate was published";
    } else if (signer === null) {
      fallbackSkipped = "no local operator key is available to sign the fallback publish";
    } else {
      try {
        fallback = await runFallbackCertificate({
          demoApiUrl: options.demoApiUrl ?? "http://127.0.0.1:8090",
          verifierUrl: options.verifierUrl ?? "http://127.0.0.1:8080",
          signer,
          approveFallback: true,
          keyFile: options.keyFile,
          keyStore: options.keyStore,
          artifactsDir,
          recordId: fallbackRecord,
        });
      } catch (error) {
        const code = codeOf(error);
        refusal = { code, detail: `the fallback certificate was not published: ${code}` };
      }
    }
  }
  const report: SeedCliReport = {
    ...prepared,
    refusal,
    ok: refusal === null && prepared.ok && (fallback === null || fallback.ok),
    fallback,
    fallbackSkipped,
  };
  const exit = refusal !== null ? 3 : report.ok ? 0 : 4;
  return { report, exit };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("-h") || args.includes("--help")) {
    process.stdout.write(USAGE);
    return;
  }
  const options = parseArgs(args);
  const { report, exit } = await runSeed(options);
  process.stdout.write(`${JSON.stringify(report)}\n`);
  if (report.refusal !== null) {
    process.stderr.write(`${JSON.stringify({ error: { code: report.refusal.code } })}\n`);
    process.exit(exit);
  }
  process.exitCode = exit;
}

const entry = process.argv[1] === undefined ? "" : pathToFileURL(path.resolve(process.argv[1])).href;
if (entry !== "" && import.meta.url === entry) {
  main().catch((error: unknown) => {
    process.stderr.write(`${JSON.stringify({ error: { code: codeOf(error) } })}\n`);
    process.exit(exitCodeFor(error));
  });
}
