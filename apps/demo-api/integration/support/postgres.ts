import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestContext } from "node:test";
import { promisify } from "node:util";
import { Pool } from "pg";

const exec = promisify(execFile);
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

/** Always creates a disposable cluster; never consumes an application DB URL. */
export async function isolatedPostgres(context: TestContext): Promise<{ pool: Pool; connectionString: string; dir: string }> {
  const bin = (await exec("pg_config", ["--bindir"])).stdout.trim();
  const dir = await mkdtemp(join(tmpdir(), "onelayer-identity-pg-"));
  const data = join(dir, "data");
  let started = false;
  let pool: Pool | undefined;
  context.after(async () => {
    try { await pool?.end(); }
    finally {
      try { if (started) await exec(join(bin, "pg_ctl"), ["-D", data, "-m", "immediate", "-w", "stop"]); }
      finally { await rm(dir, { recursive: true, force: true }); }
    }
  });
  await exec(join(bin, "initdb"), ["-D", data, "-A", "trust", "-U", "onelayer_test", "--no-locale"]);
  await exec(join(bin, "pg_ctl"), ["-D", data, "-l", join(dir, "postgres.log"), "-w", "-t", "15", "-o", `-h '' -k ${quote(dir)} -p 5432`, "start"]);
  started = true;
  const connectionString = `postgresql://onelayer_test@localhost/postgres?host=${encodeURIComponent(dir)}&port=5432`;
  pool = new Pool({ connectionString, max: 5, connectionTimeoutMillis: 3_000 });
  const migrations = new URL("../../../../db/migrations/", import.meta.url);
  for (const file of (await readdir(migrations)).filter(name => name.endsWith(".sql")).sort()) {
    await pool.query(await readFile(new URL(file, migrations), "utf8"));
  }
  return { pool, connectionString, dir };
}
