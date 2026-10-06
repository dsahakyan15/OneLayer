# On-chain Governance Extensions V1

Status: frozen for Gate E.

These instructions are additive to the pilot ABI in `onchain-state-v1.md`; they do not change any account layout.

`transition_algorithm(schema_version, hash_algorithm, tree_algorithm)` requires the current governance authority and a paused registry. `schema_version` must increase, both algorithm identifiers must be non-zero, and at least one algorithm identifier must change. The registry remains paused until a separate `resume_registry` transaction. `AlgorithmTransitioned` records the previous and new identifiers.

`rotate_governance()` requires signatures from both the current and the new governance authorities. The authorities must differ. `GovernanceRotated` records both public keys. A multisig or timelock is represented by its signer account; its policy remains outside this program.
