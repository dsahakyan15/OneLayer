// Idempotent devnet preparation executor for the live-demo seed (B4).
//
// Reuses the accepted A2 readiness assessment and A1 key store unchanged: the
// exact planned actions A2 publishes are rebuilt with the real generated
// instruction builders, signed by the local development key only when that key
// is the *exact* expected authority for the action, and sent through the JSON
// RPC writer with confirmation and a fresh recheck. When the required
// authority is missing (the current devnet governance key was permanently
// lost) the run fails with `GOVERNANCE_KEY_UNAVAILABLE` before any chain
// mutation: no key is substituted, no program is deployed, an already
// initialized registry is never mutated, and funding stays bounded to the
// rent/fee shortfall the assessment computed.
import type { Address } from "@solana/kit";
import {
  checkReadiness,
  derivePdas,
  DEVNET_GENESIS_HASH,
  type Blocker,
  type PlannedAction,
  type ReadinessItem,
  type ReadinessOptions,
  type ReadinessReport,
} from "../../../apps/demo-api/scripts/live-demo-registry.ts";
import {
  getCreateLedgerSegmentInstruction,
  getGrantOperatorInstruction,
  getInitializeRegistryInstruction,
} from "../../../packages/onchain-client/src/index.ts";
import {
  assertHex64,
  isBase58Address,
  kit,
  SeedRefusal,
  toAddress,
  waitFinalized,
  type SeedChain,
  type SeedSigner,
} from "./live-demo-seed-kit.ts";

/** Hard bound on one funding action: the rent/fee shortfall, never more. */
export const MAX_FUNDING_LAMPORTS = 500_000_000n;

export type SeedStepStatus = "READY" | "EXECUTED" | "SATISFIED" | "ACTION_REQUIRED" | "BLOCKED";

export interface SeedStep {
  id: string;
  status: SeedStepStatus;
  detail: string;
  blockers: Blocker[];
  action: PlannedAction | null;
  /** Transaction or airdrop signatures this run submitted for this step. */
  signatures: string[];
  observed: Record<string, string | number | boolean | null>;
}

export interface SeedRefusalInfo {
  code: string;
  detail: string;
}

export interface SeedOperatorInfo {
  address: string | null;
  source: ReadinessReport["operator"]["source"];
  signingKeyAvailable: boolean;
  governsRegistry: boolean;
  keyPath: string | null;
}

export interface PrepareReport {
  schema: "onelayer.live-demo.seed.v1";
  profile: ReadinessReport["profile"];
  cluster: ReadinessReport["cluster"];
  checkedAt: string;
  registryId: string;
  programId: string;
  configPda: string;
  dayUtc: number;
  operator: SeedOperatorInfo;
  prepared: boolean;
  /**
   * Chain mutations broadcast by this run (transactions + faucet credits).
   * Counted when the RPC writer accepted the submission, so a broadcast that
   * later failed or timed out its confirmation is still reported as a
   * mutation that happened.
   */
  mutations: number;
  /** Submissions started (sendTransaction / requestAirdrop called). */
  mutationsAttempted: number;
  /** Submissions the RPC writer accepted (a signature exists). */
  mutationsBroadcast: number;
  /** Broadcast submissions that reached `finalized` confirmation. */
  mutationsFinalized: number;
  steps: SeedStep[];
  refusal: SeedRefusalInfo | null;
  ok: boolean;
}

export interface PrepareOptions extends ReadinessOptions {
  /** `--prepare` opt-in: without it this is assessment only. */
  prepare: boolean;
  chain: SeedChain;
  signer?: SeedSigner | null;
  maxFundingLamports?: bigint;
}

interface ExecutedAction {
  stepId: string;
  kind: PlannedAction["kind"];
  signature: string;
  broadcast: boolean;
  finalized: boolean;
}

interface MutationTally {
  attempted: number;
  broadcast: number;
  finalized: number;
}

/**
 * A submission was accepted by the chain but its confirmation failed or timed
 * out. The signature is retained: the mutation happened and must be reported.
 */
export class BroadcastUnfinalized extends Error {
  readonly code: string;
  readonly signature: string;

  constructor(code: string, signature: string) {
    super(code);
    this.code = code;
    this.signature = signature;
  }
}

/** Gate codes: a fresh registry needs the initializer key; an existing one needs governance. */
function gateCode(action: PlannedAction): "GOVERNANCE_KEY_UNAVAILABLE" | "OPERATOR_KEY_UNAVAILABLE" {
  if (action.kind === "initialize_registry" || action.requiredSigner.role === "operator") {
    return "OPERATOR_KEY_UNAVAILABLE";
  }
  return "GOVERNANCE_KEY_UNAVAILABLE";
}

/**
 * The exact-authority gate: the local signing key must be the planned signer
 * of the action, nothing else is ever substituted. This holds for every
 * planned action including `fund_operator` — its A2 `requiredSigner` is the
 * registry's funder (the governance authority), so a missing or mismatched
 * authority refuses the funding too and the run stops before any chain
 * mutation, faucet credits included. On a fresh registry the only possible
 * authority is the initializer the same run installs, so a plan with no named
 * authority yet is checked against that initializer.
 */
export function actionGate(
  action: PlannedAction,
  signer: SeedSigner | null,
  items: readonly ReadinessItem[] = [],
): SeedRefusalInfo | null {
  const expected = expectedAuthority(action, items);
  const code = gateCode(action);
  if (expected === null) {
    return { code, detail: `the planned ${action.kind} action names no signer address; nothing is substituted` };
  }
  if (signer === null) {
    return {
      code,
      detail: `no local signing key is available for the planned ${action.kind} action as ${expected}`,
    };
  }
  if (signer.address !== expected) {
    return {
      code,
      detail:
        `local signer ${signer.address} is not the expected ${action.requiredSigner.role} ` +
        `${expected} for ${action.kind}; nothing is substituted for a missing authority`,
    };
  }
  return null;
}

function expectedAuthority(action: PlannedAction, items: readonly ReadinessItem[]): string | null {
  if (action.requiredSigner.address !== null) return action.requiredSigner.address;
  const init = items.find((entry) => entry.action?.kind === "initialize_registry")?.action ?? null;
  return init === null ? null : init.requiredSigner.address;
}

function mutatingKinds(action: PlannedAction | null): boolean {
  return (
    action !== null &&
    (action.kind === "initialize_registry" ||
      action.kind === "grant_operator" ||
      action.kind === "unpause_registry" ||
      action.kind === "create_ledger_segment" ||
      action.kind === "fund_operator")
  );
}

function numberArg(action: PlannedAction, name: string, max: number): number {
  const raw = action.args[name];
  const value = typeof raw === "number" ? raw : Number(raw);
  if (!Number.isSafeInteger(value) || value < 0 || value > max) {
    throw new SeedRefusal("PLAN_ARGS_INVALID");
  }
  return value;
}

function textArg(action: PlannedAction, name: string): string {
  const raw = action.args[name];
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 128) throw new SeedRefusal("PLAN_ARGS_INVALID");
  return raw;
}

function addressArg(action: PlannedAction, name: string): Address {
  const value = textArg(action, name);
  if (!isBase58Address(value)) throw new SeedRefusal("PLAN_ARGS_INVALID");
  return toAddress(value);
}

export interface InstructionBuild {
  instruction: ReturnType<typeof getGrantOperatorInstruction>;
  signerAddress: string;
}

/**
 * Rebuilds the exact instruction of one planned action from its plan args.
 * Account metas the plan deliberately omits (role, previous segment) are
 * re-derived from the accepted PDA derivation, and absent optional accounts
 * fall back to the program-id placeholder exactly as the generated builder
 * defines it.
 */
export async function buildInstructionForAction(
  action: PlannedAction,
  pdas: Awaited<ReturnType<typeof derivePdas>>,
): Promise<InstructionBuild> {
  switch (action.kind) {
    case "initialize_registry": {
      const initializer = action.requiredSigner.address;
      if (initializer === null || !isBase58Address(initializer)) throw new SeedRefusal("PLAN_ARGS_INVALID");
      return {
        instruction: getInitializeRegistryInstruction({
          config: addressArg(action, "configPda"),
          governance: kit.createNoopSigner(toAddress(initializer)),
          registryIdHash: assertHex64(textArg(action, "registryIdHash")),
          emergencyAuthority: addressArg(action, "emergencyAuthority"),
          schemaVersion: numberArg(action, "schemaVersion", 0xffff),
          hashAlgorithm: numberArg(action, "hashAlgorithm", 0xff),
          treeAlgorithm: numberArg(action, "treeAlgorithm", 0xff),
          anchorIntervalSeconds: numberArg(action, "anchorIntervalSeconds", 0xffff_ffff),
          maxEntriesPerDay: numberArg(action, "maxEntriesPerDay", 0xffff),
        }) as unknown as InstructionBuild["instruction"],
        signerAddress: initializer,
      };
    }
    case "grant_operator": {
      const authority = action.requiredSigner.address;
      const operator = action.args.operator;
      const rolePda = action.args.rolePda;
      if (authority === null || operator === null || rolePda === null) throw new SeedRefusal("PLAN_ARGS_INVALID");
      return {
        instruction: getGrantOperatorInstruction({
          config: addressArg(action, "configPda"),
          role: addressArg(action, "rolePda"),
          operator: addressArg(action, "operator"),
          governanceAuthority: kit.createNoopSigner(toAddress(authority)),
          permissions: numberArg(action, "permissions", 0xffff_ffff),
          validFrom: numberArg(action, "validFrom", Number.MAX_SAFE_INTEGER),
          validUntil: numberArg(action, "validUntil", Number.MAX_SAFE_INTEGER),
          keyIdHash: assertHex64(textArg(action, "keyIdHash")),
        }) as unknown as InstructionBuild["instruction"],
        signerAddress: authority,
      };
    }
    case "create_ledger_segment": {
      const operator = action.requiredSigner.address;
      const rolePda = pdas.operatorRolePda;
      const segmentPda = action.args.segmentPda;
      if (operator === null || rolePda === null || segmentPda === null) throw new SeedRefusal("PLAN_ARGS_INVALID");
      const segmentIndex = numberArg(action, "segmentIndex", 0xffff);
      const previous = segmentIndex > 0 ? pdas.segments[segmentIndex - 1] : undefined;
      return {
        instruction: getCreateLedgerSegmentInstruction({
          config: addressArg(action, "configPda"),
          role: toAddress(String(rolePda)),
          operator: kit.createNoopSigner(toAddress(operator)),
          segment: addressArg(action, "segmentPda"),
          previousSegment: previous === undefined ? undefined : previous.pda,
          dayUtc: numberArg(action, "dayUtc", 0xffff_ffff),
          segmentIndex,
          capacity: numberArg(action, "capacity", 0xffff),
        }) as unknown as InstructionBuild["instruction"],
        signerAddress: operator,
      };
    }
    default:
      throw new SeedRefusal("ACTION_NOT_AUTOMATED");
  }
}

/** Counts one submission attempt and turns finalization failures into reports. */
async function broadcastAndConfirm(
  chain: SeedChain,
  tally: MutationTally,
  submit: () => Promise<string>,
): Promise<{ signature: string; finalized: boolean }> {
  tally.attempted += 1;
  const signature = await submit();
  tally.broadcast += 1;
  try {
    await waitFinalized(chain, signature);
  } catch (error) {
    const code = error instanceof SeedRefusal ? error.code : "TRANSACTION_TIMEOUT";
    throw new BroadcastUnfinalized(code, signature);
  }
  tally.finalized += 1;
  return { signature, finalized: true };
}

async function submitSigned(
  chain: SeedChain,
  signer: SeedSigner,
  build: InstructionBuild,
  tally: MutationTally,
): Promise<{ signature: string; finalized: boolean }> {
  const { blockhash, lastValidBlockHeight } = await chain.getLatestBlockhash();
  const feePayer = kit.createNoopSigner(toAddress(signer.address));
  const message = kit.pipe(
    kit.createTransactionMessage({ version: 0 }),
    (draft) => kit.setTransactionMessageFeePayerSigner(feePayer, draft),
    (draft) =>
      kit.setTransactionMessageLifetimeUsingBlockhash(
        { blockhash: blockhash as never, lastValidBlockHeight },
        draft,
      ),
    (draft) => kit.appendTransactionMessageInstruction(build.instruction, draft),
  );
  const transaction = kit.compileTransaction(message);
  const messageBytes = Buffer.from(transaction.messageBytes);
  const signature = signer.sign(messageBytes);
  const wire = kit.getTransactionEncoder().encode({
    messageBytes: transaction.messageBytes,
    signatures: {
      ...transaction.signatures,
      [toAddress(signer.address)]: kit.signatureBytes(Uint8Array.from(signature)),
    },
  });
  const encoded = Buffer.from(wire).toString("base64");
  return broadcastAndConfirm(chain, tally, () => chain.sendTransaction(encoded));
}

async function executeAction(
  action: PlannedAction,
  chain: SeedChain,
  signer: SeedSigner | null,
  maxFundingLamports: bigint,
  pdas: Awaited<ReturnType<typeof derivePdas>>,
  tally: MutationTally,
): Promise<{ signature: string; finalized: boolean }> {
  if (action.kind === "fund_operator") {
    const lamports = BigInt(textArg(action, "lamports"));
    const to = action.args.to;
    if (typeof to !== "string" || !isBase58Address(to)) throw new SeedRefusal("PLAN_ARGS_INVALID");
    if (lamports <= 0n) throw new SeedRefusal("PLAN_ARGS_INVALID");
    if (lamports > maxFundingLamports) throw new SeedRefusal("FUNDING_EXCEEDS_BOUND");
    return broadcastAndConfirm(chain, tally, () => chain.requestAirdrop(to, lamports));
  }
  if (signer === null) throw new SeedRefusal(gateCode(action));
  const build = await buildInstructionForAction(action, pdas);
  if (build.signerAddress !== signer.address) throw new SeedRefusal(gateCode(action));
  return submitSigned(chain, signer, build, tally);
}

function toSteps(report: ReadinessReport, executed: ExecutedAction[]): SeedStep[] {
  return report.items.map((entry: ReadinessItem) => {
    const done = executed.filter((candidate) => candidate.stepId === entry.id);
    const signatures = done.map((candidate) => candidate.signature);
    const status: SeedStepStatus =
      done.length > 0 && entry.status === "READY"
        ? "EXECUTED"
        : entry.status === "READY"
          ? "READY"
          : entry.status === "ACTION_REQUIRED"
            ? "ACTION_REQUIRED"
            : "BLOCKED";
    const unfinalized = done.filter((candidate) => !candidate.finalized);
    return {
      id: entry.id,
      status,
      detail:
        done.length > 0
          ? unfinalized.length > 0
            ? `${entry.detail} (broadcast by this run, confirmation not finalized)`
            : `${entry.detail} (executed by this run)`
          : entry.detail,
      blockers: entry.blockers,
      action: entry.action,
      signatures,
      observed: {
        ...entry.observed,
        ...(done.length > 0 ? { executedKinds: done.map((candidate) => candidate.kind).join(",") } : {}),
        ...(unfinalized.length > 0 ? { unfinalizedSignatures: unfinalized.map((candidate) => candidate.signature).join(",") } : {}),
      },
    };
  });
}

/**
 * Assessment plus, under the explicit `--prepare` opt-in, idempotent
 * preparation. Every execution is preceded by a fresh assessment recheck, so a
 * satisfied step is never executed twice, and a missing authority aborts the
 * whole run before the first mutation.
 */
export async function prepareDemoChain(options: PrepareOptions): Promise<PrepareReport> {
  const chain = options.chain;
  const signer = options.signer ?? null;
  const maxFunding = options.maxFundingLamports ?? MAX_FUNDING_LAMPORTS;
  const executed: ExecutedAction[] = [];
  const tally: MutationTally = { attempted: 0, broadcast: 0, finalized: 0 };
  let refusal: SeedRefusalInfo | null = null;

  if (options.prepare) {
    // The devnet genesis is fixed: nothing is ever prepared against another
    // cluster, and the refusal lands before the first mutation.
    try {
      await assertDevnetGenesis(chain);
    } catch (error) {
      const code = error instanceof SeedRefusal ? error.code : "RPC_UNREACHABLE";
      const assessment = await checkReadiness({ ...options, chain });
      return {
        schema: "onelayer.live-demo.seed.v1",
        profile: assessment.profile,
        cluster: assessment.cluster,
        checkedAt: assessment.checkedAt,
        registryId: assessment.registryId,
        programId: assessment.programId,
        configPda: assessment.configPda,
        dayUtc: assessment.dayUtc,
        operator: assessment.operator,
        prepared: true,
        mutations: 0,
        mutationsAttempted: 0,
        mutationsBroadcast: 0,
        mutationsFinalized: 0,
        steps: toSteps(assessment, []),
        refusal: { code, detail: `chain preconditions failed before any preparation: ${code}` },
        ok: false,
      };
    }
  }

  const assessment = await checkReadiness({ ...options, chain });

  if (options.prepare) {
    // Pre-mutation gate: a required action whose exact authority is missing
    // aborts the whole run before the first mutation.
    const needed = assessment.items.filter((entry) => mutatingKinds(entry.action) && entry.status !== "READY");
    for (const entry of needed) {
      const gate = actionGate(entry.action as PlannedAction, signer, assessment.items);
      if (gate !== null) {
        refusal = gate;
        break;
      }
    }
  }

  if (options.prepare && refusal === null) {
    const kinds: PlannedAction["kind"][] = [
      "initialize_registry",
      "grant_operator",
      "fund_operator",
      "create_ledger_segment",
    ];
    for (const kind of kinds) {
      const fresh = await checkReadiness({ ...options, chain });
      const item = fresh.items.find((entry) => entry.action?.kind === kind && entry.status !== "READY");
      if (item === undefined || item.action === null) continue;
      const gate = actionGate(item.action, signer, fresh.items);
      if (gate !== null) {
        refusal = gate;
        break;
      }
      const day = fresh.dayUtc;
      const pdas = await derivePdas(fresh.operator.address, day);
      try {
        const result = await executeAction(item.action, chain, signer, maxFunding, pdas, tally);
        executed.push({ stepId: item.id, kind, signature: result.signature, broadcast: true, finalized: result.finalized });
      } catch (error) {
        if (error instanceof BroadcastUnfinalized) {
          // The submission was accepted: the mutation happened and is counted.
          executed.push({ stepId: item.id, kind, signature: error.signature, broadcast: true, finalized: false });
          refusal = {
            code: error.code,
            detail: `the ${kind} action was broadcast as ${error.signature} but did not finalize: ${error.code}`,
          };
        } else {
          refusal =
            error instanceof SeedRefusal
              ? { code: error.code, detail: `the ${kind} action was not applied: ${error.code}` }
              : { code: "SEED_INTERNAL_ERROR", detail: `the ${kind} action failed` };
        }
        break;
      }
    }
  }

  const finalReport = options.prepare ? await checkReadiness({ ...options, chain }) : assessment;
  const steps = toSteps(finalReport, executed);
  return {
    schema: "onelayer.live-demo.seed.v1",
    profile: finalReport.profile,
    cluster: finalReport.cluster,
    checkedAt: finalReport.checkedAt,
    registryId: finalReport.registryId,
    programId: finalReport.programId,
    configPda: finalReport.configPda,
    dayUtc: finalReport.dayUtc,
    operator: finalReport.operator,
    prepared: options.prepare,
    mutations: tally.broadcast,
    mutationsAttempted: tally.attempted,
    mutationsBroadcast: tally.broadcast,
    mutationsFinalized: tally.finalized,
    steps,
    refusal,
    ok: refusal === null && steps.every((step) => step.status === "READY" || step.status === "EXECUTED"),
  };
}

export async function assertDevnetGenesis(chain: SeedChain): Promise<void> {
  const health = await chain.getHealth();
  if (health !== "ok") throw new SeedRefusal("RPC_UNREACHABLE");
  const genesis = await chain.getGenesisHash();
  if (genesis !== DEVNET_GENESIS_HASH) throw new SeedRefusal("CLUSTER_NOT_DEVNET");
}
