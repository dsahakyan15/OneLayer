// Disposable local Solana validator for chain integration tests.
//
// Never touches devnet/mainnet: the validator binds to 127.0.0.1 on random
// free ports, keeps its ledger in a fresh temporary directory and is killed
// (whole process group) in test teardown. Program binaries are built from the
// repository sources into a temporary cache keyed by the source digest, so a
// stale `target/deploy` artifact can never be what the test exercises.
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { createServer } from "node:net";
import { createSocket } from "node:dgram";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestContext } from "node:test";
import { promisify } from "node:util";

const exec = promisify(execFile);

export interface SbfProgramSource {
  /** Crate directory containing Cargo.toml. */
  crateDir: string;
  /** Output library name (`<lib>.so`). */
  libName: string;
  /** Extra files that influence the build (lockfiles, workspace manifests). */
  extraInputs?: string[];
}

export interface BuiltProgram {
  so: string;
  sha256: string;
  cached: boolean;
}

async function sourceFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await sourceFiles(path));
    else if (entry.name.endsWith(".rs") || entry.name === "Cargo.toml" || entry.name === "Cargo.lock") out.push(path);
  }
  return out.sort();
}

/** Builds (or reuses a digest-keyed cached build of) an SBF program. */
export async function buildSbfProgram(source: SbfProgramSource): Promise<BuiltProgram> {
  const files = [...await sourceFiles(join(source.crateDir, "src")), join(source.crateDir, "Cargo.toml"), ...(source.extraInputs ?? [])];
  const digest = createHash("sha256");
  for (const file of files) {
    if (!existsSync(file)) continue;
    digest.update(file.replace(source.crateDir, "")).update("\0").update(await readFile(file)).update("\0");
  }
  const key = digest.digest("hex").slice(0, 24);
  const cache = join(tmpdir(), "onelayer-sbf-cache");
  const outDir = join(cache, `${source.libName}-${key}`);
  const so = join(outDir, `${source.libName}.so`);
  let cached = true;
  if (!existsSync(so)) {
    cached = false;
    await mkdir(outDir, { recursive: true });
    await exec("cargo", [
      "build-sbf", "--offline",
      "--manifest-path", join(source.crateDir, "Cargo.toml"),
      "--sbf-out-dir", outDir,
    ], {
      env: { ...process.env, CARGO_TARGET_DIR: join(cache, `target-${source.libName}`) },
      maxBuffer: 64 * 1024 * 1024,
      timeout: 15 * 60_000,
    });
  }
  const sha256 = createHash("sha256").update(await readFile(so)).digest("hex");
  return { so, sha256, cached };
}

async function tcpFree(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const server = createServer();
    server.once("error", () => resolve(false));
    server.listen({ port, host: "127.0.0.1", exclusive: true }, () => server.close(() => resolve(true)));
  });
}

async function udpFree(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const socket = createSocket("udp4");
    socket.once("error", () => { socket.close(); resolve(false); });
    socket.bind(port, "127.0.0.1", () => socket.close(() => resolve(true)));
  });
}

/** A contiguous free TCP+UDP range; the validator needs many dynamic ports. */
async function freeRange(size: number): Promise<number> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const base = 20_000 + Math.floor(Math.random() * 35_000);
    let ok = true;
    for (let port = base; port < base + size && ok; port += 1) ok = await tcpFree(port) && await udpFree(port);
    if (ok) return base;
  }
  throw new Error("no free local port range for solana-test-validator");
}

export interface LocalValidator {
  rpcUrl: string;
  ledger: string;
  version: string;
  /** Stops the validator; idempotent. */
  stop(): Promise<void>;
}

export interface ValidatorProgram {
  programId: string;
  so: string;
}

export async function rpcCall(rpcUrl: string, method: string, params: unknown[] = []): Promise<any> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    signal: AbortSignal.timeout(15_000),
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const payload = await response.json() as { result?: unknown; error?: { message?: string } };
  if (payload.error) throw new Error(`${method}: ${payload.error.message ?? "RPC error"}`);
  return payload.result;
}

/** Signals a whole process group; the group outlives a dead watchdog leader. */
function signalGroup(pgid: number, signal: NodeJS.Signals | 0): boolean {
  try { process.kill(-pgid, signal); return true; } catch { return false; }
}

async function stopGroup(pgid: number): Promise<void> {
  const gone = async (ms: number) => {
    const deadline = performance.now() + ms;
    while (performance.now() < deadline) {
      if (!signalGroup(pgid, 0)) return true;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    return !signalGroup(pgid, 0);
  };
  // Independent of the watchdog's state: if it already died, the validator is
  // still a member of the same group and is signalled directly.
  signalGroup(pgid, "SIGTERM");
  if (await gone(5_000)) return;
  signalGroup(pgid, "SIGKILL");
  if (!await gone(5_000)) throw new Error(`validator process group ${pgid} did not exit`);
}

const START_ATTEMPTS = 3;

/**
 * Starts `solana-test-validator` with the given programs preloaded and waits
 * for RPC health. Teardown is registered on the test context before any
 * process is spawned; a process `exit` hook and a bash watchdog (for SIGKILL of
 * this process) are further lines of defence. A start that fails (e.g. a port
 * taken between probing and binding) is torn down and retried on new ports.
 */
export async function startLocalValidator(context: TestContext, programs: ValidatorProgram[]): Promise<LocalValidator> {
  const version = (await exec("solana-test-validator", ["--version"])).stdout.trim();
  const dir = await mkdtemp(join(tmpdir(), "onelayer-validator-"));
  const ledger = join(dir, "ledger");
  const groups = new Set<number>();
  const exitHook = () => { for (const pgid of groups) signalGroup(pgid, "SIGKILL"); };
  process.on("exit", exitHook);
  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    try {
      for (const pgid of groups) await stopGroup(pgid);
    } finally {
      process.off("exit", exitHook);
      await rm(dir, { recursive: true, force: true });
    }
  };
  context.after(stop);

  const failures: string[] = [];
  for (let attempt = 1; attempt <= START_ATTEMPTS; attempt += 1) {
    const base = await freeRange(40);
    const rpcPort = base;
    const args = [
      "--ledger", ledger, "--reset", "--quiet",
      "--bind-address", "127.0.0.1",
      "--rpc-port", String(rpcPort),               // websocket uses rpcPort + 1
      "--faucet-port", String(base + 2),
      "--gossip-port", String(base + 3),
      "--dynamic-port-range", `${base + 4}-${base + 39}`,
      "--limit-ledger-size", "50000000",
    ];
    for (const program of programs) args.push("--bpf-program", program.programId, program.so);
    // A bash watchdog owns the validator: it kills it (and removes the ledger)
    // if this Node process disappears without running hooks (e.g. SIGKILL), and
    // on TERM it reaps the validator before exiting so teardown never races rm.
    const watchdog = [
      // The validator keeps the stderr pipe; the watchdog itself must never die
      // of SIGPIPE writing a job notice once the Node side is gone.
      '"$@" & v=$!',
      'exec 2>/dev/null; trap "" PIPE',
      'trap \'kill -9 $v 2>/dev/null; wait $v; exit 0\' TERM INT HUP',
      'while kill -0 "$ONELAYER_PARENT_PID" 2>/dev/null && kill -0 $v 2>/dev/null; do sleep 1; done',
      'kill -9 $v 2>/dev/null; wait $v',
      'kill -0 "$ONELAYER_PARENT_PID" 2>/dev/null || rm -rf "$ONELAYER_VALIDATOR_DIR"',
    ].join("\n");
    const child: ChildProcess = spawn("bash", ["-c", watchdog, "watchdog", "solana-test-validator", ...args], {
      cwd: dir, detached: true, stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, ONELAYER_PARENT_PID: String(process.pid), ONELAYER_VALIDATOR_DIR: dir },
    });
    if (child.pid === undefined) throw new Error("failed to spawn solana-test-validator");
    const pgid = child.pid;
    groups.add(pgid);
    let stderr = "";
    child.stderr?.on("data", chunk => { stderr = (stderr + String(chunk)).slice(-4_000); });

    const rpcUrl = `http://127.0.0.1:${rpcPort}`;
    const deadline = performance.now() + 90_000;
    let failure: string | null = null;
    for (;;) {
      if (child.exitCode !== null || child.signalCode !== null) {
        failure = `exited early (${child.exitCode ?? child.signalCode}): ${stderr}`;
        break;
      }
      try {
        if (await rpcCall(rpcUrl, "getHealth") === "ok" && await rpcCall(rpcUrl, "getSlot", [{ commitment: "finalized" }]) > 0) break;
      } catch { /* not up yet */ }
      if (performance.now() > deadline) { failure = `did not become healthy: ${stderr}`; break; }
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    if (failure === null) {
      if (!(await stat(ledger)).isDirectory()) throw new Error("validator ledger was not created in the temporary directory");
      return { rpcUrl, ledger, version, stop };
    }
    failures.push(`attempt ${attempt} on ports ${base}-${base + 39}: ${failure}`);
    await stopGroup(pgid);
    groups.delete(pgid);
    await rm(ledger, { recursive: true, force: true });
  }
  throw new Error(`solana-test-validator failed to start:\n${failures.join("\n")}`);
}
