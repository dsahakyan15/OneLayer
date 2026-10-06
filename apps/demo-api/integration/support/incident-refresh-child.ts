// Child process for the hard-crash (SIGKILL) case of incident-chain.test.ts.
// Runs a real refresh against the local validator and a disposable database,
// announces "HANG" once it has read N transactions inside the open DB
// transaction, then blocks until the parent kills it.
import { getAddressEncoder, address } from "@solana/kit";
import { Pool } from "pg";
import { refreshIncidentIndex, type TransactionLogs } from "../../src/incident-index.ts";
import { PostgresIncidentStore } from "../../src/incident-store.ts";
import { SolanaIncidentRpc } from "../../src/solana-rpc.ts";

const env = (name: string): string => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};
const hangAt = Number(env("CHILD_HANG_AT"));

class HangingRpc extends SolanaIncidentRpc {
  reads = 0;
  override async getTransactionLogs(signature: string): Promise<TransactionLogs | null> {
    this.reads += 1;
    if (this.reads === hangAt) {
      process.stdout.write("HANG\n");
      await new Promise(() => undefined);
    }
    return super.getTransactionLogs(signature);
  }
}

const config = env("CHILD_CONFIG");
const pool = new Pool({ connectionString: env("CHILD_DATABASE_URL"), max: 2 });
await refreshIncidentIndex(
  { registryId: env("CHILD_REGISTRY_ID"), programId: env("CHILD_PROGRAM_ID"), configAddress: config, configBytes: new Uint8Array(getAddressEncoder().encode(address(config))) },
  new HangingRpc(env("CHILD_RPC_URL")),
  new PostgresIncidentStore(pool, config),
);
process.stdout.write("DONE\n");
await pool.end();
