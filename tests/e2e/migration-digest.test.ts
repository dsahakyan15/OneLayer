/**
 * Migration digest regression tests for ticket 07 review N4.
 *
 * The devnet-demo launcher records the SHA-256 of every applied migration and
 * must now fail startup when a previously applied migration file changed,
 * disappeared, or has no usable recorded digest. Each scenario runs the real
 * launcher with the real psql against a disposable PostgreSQL cluster created
 * under a temp directory, over a copy of the checked-in migrations and
 * fixtures. No application database and no repository file is touched.
 *
 * The suite skips when PostgreSQL server tools are unavailable. CI installs
 * PostgreSQL before the `tests/e2e/*.test.ts` step so these scenarios execute.
 */
import assert from "node:assert/strict";
import { execFile, execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, cp, mkdir, mkdtemp, readFile, readdir, rm, unlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test, { type TestContext } from "node:test";

const execFileAsync = promisify(execFile);
const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
const nativeSource = join(repoRoot, "deploy", "devnet-demo", "native");

type MigrationRow = { version: string; sha256: string; appliedAt: string };
type RunResult = { code: number; stdout: string; stderr: string };

interface DigestHarness {
  /** Runs the real launcher in 'migrate' mode inside the synthetic repo copy. */
  run(): Promise<RunResult>;
  rows(): Promise<MigrationRow[]>;
  versions(): Promise<string[]>;
  fileDigest(version: string): Promise<string>;
  appliedAt(version: string): Promise<string>;
  /** Increases exactly once per run that reaches the fixture step. */
  fixtureGeneration(): Promise<number>;
  /** True when the named relation exists in the migrated database. */
  relationExists(name: string): Promise<boolean>;
  /** Entries left in the launcher's private temp directory; must be empty. */
  tempLeftovers(): Promise<string[]>;
  tamper(version: string): Promise<void>;
  injectFailure(version: string): Promise<void>;
  restore(): Promise<void>;
  remove(version: string): Promise<void>;
  /** Emulates a database created before the runner recorded digests at all. */
  dropDigestColumn(): Promise<void>;
  setDigest(version: string, digest: string): Promise<void>;
}

function runProcess(command: string, args: string[], options: { cwd?: string; env: NodeJS.ProcessEnv; input?: string }): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: options.cwd, env: options.env, stdio: [options.input === undefined ? "ignore" : "pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", code => resolve({ code: code ?? -1, stdout, stderr }));
    if (options.input !== undefined && child.stdin) child.stdin.end(options.input);
  });
}

async function unusedPort(): Promise<number> {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function writeExecutable(path: string, contents: string): Promise<void> {
  await writeFile(path, contents);
  await chmod(path, 0o755);
}

function rowOf(rows: MigrationRow[], version: string): MigrationRow {
  const row = rows.find(item => item.version === version);
  assert.ok(row, "schema_migration must have a row for " + version);
  return row as MigrationRow;
}

async function fileDigestOf(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function migrationNames(repo: string): Promise<string[]> {
  const entries = await readdir(join(repo, "db", "migrations"));
  return entries.filter(name => name.endsWith(".sql")).sort();
}

/** Builds a synthetic repo copy; the checked-in files are only read. */
async function prepareRepo(repo: string): Promise<Map<string, string>> {
  await mkdir(join(repo, "deploy", "devnet-demo", "scripts"), { recursive: true });
  await mkdir(join(repo, "db"), { recursive: true });
  await cp(nativeSource, join(repo, "deploy", "devnet-demo", "native"));
  await chmod(join(repo, "deploy", "devnet-demo", "native"), 0o755);
  // The real initialize-runtime writes tmpfs secrets and Solana keys; the
  // migrate path only needs a successful runtime step.
  await writeExecutable(join(repo, "deploy", "devnet-demo", "scripts", "initialize-runtime"), "#!/bin/sh\nexit 0\n");
  await cp(join(repoRoot, "db", "migrations"), join(repo, "db", "migrations"), { recursive: true });
  await cp(join(repoRoot, "db", "fixtures"), join(repo, "db", "fixtures"), { recursive: true });
  const originals = new Map<string, string>();
  for (const version of await migrationNames(repo)) {
    originals.set(version, await readFile(join(repo, "db", "migrations", version), "utf8"));
  }
  return originals;
}

function postgresBinDir(): string | undefined {
  try {
    const bin = execFileSync("pg_config", ["--bindir"], { encoding: "utf8" }).trim();
    if (bin && ["pg_ctl", "initdb", "psql", "pg_isready"].every(tool => existsSync(join(bin, tool)))) return bin;
  } catch {
    // PostgreSQL is not installed; the caller skips the scenarios.
  }
  return undefined;
}

async function makeHarness(context: TestContext): Promise<DigestHarness | undefined> {
  const bin = postgresBinDir();
  if (!bin) {
    context.skip("PostgreSQL server tools (pg_config --bindir) are not available on PATH");
    return undefined;
  }
  const root = await mkdtemp(join(tmpdir(), "onelayer-migration-digest-"));
  const repo = join(root, "repo");
  const originals = await prepareRepo(repo);
  const shimBin = join(root, "shim-bin");
  await mkdir(shimBin, { recursive: true });
  // Force the launcher onto the PATH tools instead of a brew installation.
  await writeExecutable(join(shimBin, "brew"), "#!/bin/sh\nexit 1\n");
  // Task-local state only: HOME stays inherited, and the launcher's private
  // temp directory is redirected into this test's own directory.
  const taskStateDir = join(root, "state");
  await mkdir(taskStateDir, { recursive: true });
  const tempDir = join(root, "tmp");
  await mkdir(tempDir, { recursive: true });
  const port = await unusedPort();
  const dataDir = join(repo, "deploy", "devnet-demo", ".runtime", "native", "postgres");
  context.after(async () => {
    if (existsSync(join(dataDir, "PG_VERSION"))) {
      await execFileAsync(join(bin, "pg_ctl"), ["-D", dataDir, "-m", "immediate", "-w", "stop"]).catch(() => undefined);
    }
    await rm(root, { recursive: true, force: true });
  });
  const baseEnv = {
    PATH: shimBin + ":" + bin + ":" + (process.env.PATH ?? ""),
    XDG_STATE_HOME: taskStateDir,
    ONELAYER_NATIVE_PG_PORT: String(port),
    TMPDIR: tempDir,
  };
  const psqlArgs = ["-X", "-h", "127.0.0.1", "-p", String(port), "-U", "onelayer_demo", "-d", "onelayer_demo", "-At", "-F", "|", "-v", "ON_ERROR_STOP=1"];
  // psql substitutes :'variables' only in files and stdin, so the helper always
  // feeds SQL through stdin.
  const script = async (sql: string, variables: Record<string, string> = {}): Promise<string> => {
    const args = psqlArgs.slice();
    for (const [name, value] of Object.entries(variables)) args.push("-v", name + "=" + value);
    const result = await runProcess(join(bin, "psql"), args, { env: { ...process.env, ...baseEnv }, input: sql + "\n" });
    assert.equal(result.code, 0, result.stderr);
    return result.stdout.trim();
  };
  const rows = async (): Promise<MigrationRow[]> => {
    const text = await script("SELECT version, coalesce(sha256, ''), applied_at::text FROM schema_migration ORDER BY version;");
    if (!text) return [];
    return text.split("\n").map(line => {
      const [version, sha256, appliedAt] = line.split("|");
      return { version, sha256, appliedAt };
    });
  };
  const migrationFile = (version: string) => join(repo, "db", "migrations", version);
  return {
    async run() {
      return runProcess("bash", [join(repo, "deploy", "devnet-demo", "native"), "migrate"], { cwd: repo, env: { ...process.env, ...baseEnv } });
    },
    rows,
    async versions() { return migrationNames(repo); },
    async fileDigest(version) { return fileDigestOf(migrationFile(version)); },
    async appliedAt(version) { return rowOf(await rows(), version).appliedAt; },
    async fixtureGeneration() {
      return Number(await script("SELECT coalesce(max(fixture_generation), 0) FROM synthetic_registry_record;"));
    },
    async relationExists(name) {
      return (await script("SELECT to_regclass('public." + name + "') IS NOT NULL;")) === "t";
    },
    async tempLeftovers() { return readdir(tempDir); },
    async tamper(version) { await writeFile(migrationFile(version), originals.get(version) + "\n-- tampered by migration-digest test\n"); },
    async injectFailure(version) { await writeFile(migrationFile(version), originals.get(version) + "\nSELECT * FROM onelayer_migration_digest_test_missing_table;\n"); },
    async restore() {
      for (const [version, text] of originals) await writeFile(migrationFile(version), text);
    },
    async remove(version) { await unlink(migrationFile(version)); },
    async dropDigestColumn() { await script("ALTER TABLE schema_migration DROP COLUMN sha256;"); },
    async setDigest(version, digest) {
      await script("UPDATE schema_migration SET sha256 = :'digest' WHERE version = :'version';", { version, digest });
    },
  };
}

test("records a verified digest for every applied migration and does not re-apply on a second run", async context => {
  const harness = await makeHarness(context);
  if (!harness) return;
  const first = await harness.run();
  assert.equal(first.code, 0, first.stderr + first.stdout);
  const versions = await harness.versions();
  const applied = await harness.rows();
  assert.deepEqual(applied.map(row => row.version), versions, "every checked-in migration must be recorded");
  for (const version of versions) {
    assert.equal(rowOf(applied, version).sha256, await harness.fileDigest(version), "the recorded digest must cover the applied file");
  }
  const generation = await harness.fixtureGeneration();
  const stamps = applied.map(row => row.version + "=" + row.appliedAt).join(",");
  const second = await harness.run();
  assert.equal(second.code, 0, second.stderr + second.stdout);
  const after = await harness.rows();
  assert.equal(after.map(row => row.version + "=" + row.appliedAt).join(","), stamps, "an already-applied migration must not be applied again");
  assert.equal(await harness.fixtureGeneration(), generation + 1, "the second run must still reach the fixture step");
  assert.deepEqual(await harness.tempLeftovers(), [], "the launcher must remove its private temp directory");
});

test("fails closed when an applied migration file changed or disappeared", async context => {
  const harness = await makeHarness(context);
  if (!harness) return;
  const versions = await harness.versions();
  const version = versions[0];
  const first = await harness.run();
  assert.equal(first.code, 0, first.stderr + first.stdout);
  const recorded = await harness.fileDigest(version);
  const stamp = await harness.appliedAt(version);
  const generation = await harness.fixtureGeneration();

  await harness.tamper(version);
  const changed = await harness.run();
  assert.notEqual(changed.code, 0, "a changed applied migration must fail startup");
  const output = changed.stderr + changed.stdout;
  assert.ok(output.includes(version), output);
  assert.ok(output.includes(recorded), "the failure must name the recorded digest");
  assert.ok(output.includes(await harness.fileDigest(version)), "the failure must name the current file digest");
  assert.equal(await harness.appliedAt(version), stamp, "the tampered file must not be applied");
  assert.equal(await harness.fixtureGeneration(), generation, "a failing verification must not reach the fixture step");

  await harness.restore();
  await harness.remove(versions[versions.length - 1]);
  const missing = await harness.run();
  assert.notEqual(missing.code, 0, "a recorded migration without a file must fail startup");
  assert.ok(missing.stderr.includes("no file in db/migrations"), missing.stderr);
  assert.equal(await harness.fixtureGeneration(), generation, "a failing verification must not reach the fixture step");
});

test("fails closed on a missing or unusable digest before the fixture step", async context => {
  const harness = await makeHarness(context);
  if (!harness) return;
  const version = (await harness.versions())[0];
  const first = await harness.run();
  assert.equal(first.code, 0, first.stderr + first.stdout);
  const generation = await harness.fixtureGeneration();

  // A database created before the runner recorded digests has the table but no
  // digest column; rows can never be verified again, so startup must fail.
  await harness.dropDigestColumn();
  const legacy = await harness.run();
  assert.notEqual(legacy.code, 0, "a recorded migration without its digest must fail closed");
  assert.ok(legacy.stderr.includes("no recorded digest"), legacy.stderr);
  assert.equal(await harness.fixtureGeneration(), generation, "verification must run before the fixture step");

  await harness.setDigest(version, "not-a-sha256");
  const unusable = await harness.run();
  assert.notEqual(unusable.code, 0, "an unusable recorded digest must fail closed");
  assert.ok(unusable.stderr.includes("not-a-sha256"), unusable.stderr);
  assert.ok(unusable.stderr.includes(await harness.fileDigest(version)), unusable.stderr);
});

test("applies the migration file and its checksum row in one transaction", async context => {
  const harness = await makeHarness(context);
  if (!harness) return;
  const versions = await harness.versions();
  const version = versions.find(name => name.startsWith("0017_")) as string;
  assert.ok(version, "0017 (which creates wf_version_exclusion) must be in db/migrations");
  const relation = "wf_version_exclusion";

  await harness.injectFailure(version);
  const failed = await harness.run();
  assert.notEqual(failed.code, 0, "a migration whose SQL fails must fail the run");
  const applied = await harness.rows();
  assert.ok(!applied.some(row => row.version === version), "a failed migration must not leave a checksum row");
  assert.ok(applied.some(row => row.version === versions[0]), "migrations applied before the failure stay committed");
  assert.equal(await harness.relationExists(relation), false, "a failed migration must not leave its relation behind");
  assert.deepEqual(await harness.tempLeftovers(), [], "a failed run must still remove its private temp directory");

  await harness.restore();
  const retry = await harness.run();
  assert.equal(retry.code, 0, retry.stderr + retry.stdout);
  assert.equal(rowOf(await harness.rows(), version).sha256, await harness.fileDigest(version));
  assert.equal(await harness.relationExists(relation), true, "the retry must apply the migration");
});
