// Public surface of the on-chain client. Everything under `generated/` comes
// from `onchain/idl/onelayer_registry.json` via Codama and is checked by
// `npm run check-drift`. Only PDA helpers whose seeds the Anchor IDL does not
// describe are written here, and they use Kit primitives rather than manual
// byte layout (OL-C-32).
import {
  getAddressEncoder,
  getProgramDerivedAddress,
  getU16Encoder,
  type Address,
  type ProgramDerivedAddress,
} from "@solana/kit";

export * from "./generated/index.ts";
export { ONELAYER_REGISTRY_PROGRAM_ADDRESS } from "./generated/programs/index.ts";

import { ONELAYER_REGISTRY_PROGRAM_ADDRESS } from "./generated/programs/index.ts";

const textEncoder = new TextEncoder();
const addresses = getAddressEncoder();

export interface ProgramOptions {
  programAddress?: Address;
}

function programAddress(options: ProgramOptions): Address {
  return options.programAddress ?? (ONELAYER_REGISTRY_PROGRAM_ADDRESS as Address);
}

/** seeds = ["registry", registry_id_hash] */
export async function findRegistryConfigPda(
  registryIdHash: Uint8Array,
  options: ProgramOptions = {},
): Promise<ProgramDerivedAddress> {
  if (registryIdHash.length !== 32) throw new RangeError("registryIdHash must be 32 bytes");
  return getProgramDerivedAddress({
    programAddress: programAddress(options),
    seeds: [textEncoder.encode("registry"), registryIdHash],
  });
}

/** seeds = ["ledger", config, u32_be(day_utc), u16_le(segment_index)] */
export async function findLedgerSegmentPda(
  seeds: { config: Address; dayUtc: number; segmentIndex: number },
  options: ProgramOptions = {},
): Promise<ProgramDerivedAddress> {
  if (!Number.isInteger(seeds.dayUtc) || seeds.dayUtc < 0 || seeds.dayUtc > 0xffff_ffff) {
    throw new RangeError("dayUtc is out of range");
  }
  if (!Number.isInteger(seeds.segmentIndex) || seeds.segmentIndex < 0 || seeds.segmentIndex > 0xffff) {
    throw new RangeError("segmentIndex is out of range");
  }
  const dayUtc = new Uint8Array(4);
  new DataView(dayUtc.buffer).setUint32(0, seeds.dayUtc, false);
  return getProgramDerivedAddress({
    programAddress: programAddress(options),
    seeds: [
      textEncoder.encode("ledger"),
      addresses.encode(seeds.config),
      dayUtc,
      getU16Encoder().encode(seeds.segmentIndex),
    ],
  });
}

/** seeds = ["incident", config, u64_be(incident_sequence)] */
export async function findIncidentNoticePda(
  seeds: { config: Address; incidentSequence: bigint },
  options: ProgramOptions = {},
): Promise<ProgramDerivedAddress> {
  if (seeds.incidentSequence < 0n || seeds.incidentSequence > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError("incidentSequence is out of range");
  }
  const sequence = new Uint8Array(8);
  new DataView(sequence.buffer).setBigUint64(0, seeds.incidentSequence, false);
  return getProgramDerivedAddress({
    programAddress: programAddress(options),
    seeds: [textEncoder.encode("incident"), addresses.encode(seeds.config), sequence],
  });
}
