// Pinned chain identity for the workflow publication runtime (M4).
//
// The deployment cluster is an explicit label, never a default. The expected
// genesis hash is pinned out of band: a built-in constant for the public
// clusters, or an explicit `genesisHash` for local/unknown clusters. The
// publisher compares the connected RPC's `getGenesisHash` against it before it
// reserves or signs anything, so a mislabeled or substituted RPC endpoint fails
// closed instead of binding an approval to the wrong chain.
export const GENESIS_HASH = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
export const CLUSTER_LABEL = /^solana:[a-z0-9-]{1,32}$/;

/** Genesis hashes of the public clusters, pinned from the live networks. */
export const KNOWN_GENESIS_HASHES: Readonly<Record<string, string>> = Object.freeze({
  "solana:devnet": "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
  "solana:testnet": "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
  "solana:mainnet-beta": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
});

export class PublicationIdentityError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.code = code; }
}

export function assertClusterLabel(value: unknown): string {
  if (typeof value !== "string" || !CLUSTER_LABEL.test(value)) throw new PublicationIdentityError("PUBLICATION_IDENTITY_UNCONFIGURED");
  return value;
}

export function assertGenesisHash(value: unknown): string {
  if (typeof value !== "string" || !GENESIS_HASH.test(value)) throw new PublicationIdentityError("PUBLICATION_CHAIN_IDENTITY_INVALID");
  return value;
}

/**
 * The expected genesis hash for an explicit cluster. A built-in public-cluster
 * constant is used only when the label names exactly that network; every other
 * label (`solana:local`, a private cluster, a typo) requires an explicit
 * `genesisHash` and otherwise refuses. There is deliberately no fallback.
 */
export function expectedGenesisHash(cluster: string, explicit?: string): string {
  assertClusterLabel(cluster);
  if (explicit !== undefined && explicit !== "") return assertGenesisHash(explicit);
  const known = KNOWN_GENESIS_HASHES[cluster];
  if (known === undefined) throw new PublicationIdentityError("PUBLICATION_CHAIN_IDENTITY_UNCONFIGURED");
  return known;
}
