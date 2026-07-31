# OneLayer Recovery Lab

This lab is fixed to Compose project `onelayer-recovery-lab` and synthetic database `onelayer_fixture`. Test credentials, the 32-byte test KEK, and recovery shares live only under `/dev/shm/onelayer-recovery-lab-secrets`; they are not repository files. Restore copies three selected shares into `/run/onelayer-recovery` tmpfs.

The `snapshot` profile starts the coordinator with source and storage access but no share. Remove that container before starting the `restore` profile. The clean-room restore service joins storage, key-holder, and restore networks but never the source network.

Destructive fixture scripts require `DESTROY_ONELAYER_FIXTURE=yes`, verify Compose and fixture labels, and name their single target explicitly. They do not prune Docker resources.

Run the synthetic drill from the repository root:

```bash
deploy/recovery-lab/scripts/initialize-lab
docker compose -p onelayer-recovery-lab -f deploy/recovery-lab/compose.yaml up -d source-db custodian-a custodian-b custodian-c
docker compose -p onelayer-recovery-lab -f deploy/recovery-lab/compose.yaml --profile snapshot up -d snapshot-coordinator
deploy/recovery-lab/scripts/create-snapshot 00000000000000000000000000000001 1
DESTROY_ONELAYER_FIXTURE=yes deploy/recovery-lab/scripts/corrupt-replica 00000000000000000000000000000001.cbor
DESTROY_ONELAYER_FIXTURE=yes deploy/recovery-lab/scripts/destroy-primary
docker compose -p onelayer-recovery-lab -f deploy/recovery-lab/compose.yaml --profile restore up -d key-holder-1 key-holder-2 key-holder-3 key-holder-4 key-holder-5 clean-room-db clean-room-restore
docker stop onelayer-recovery-lab-custodian-b-1
deploy/recovery-lab/scripts/restore-clean-room 00000000000000000000000000000001.cbor
deploy/recovery-lab/scripts/reconcile-anchor "$SAVED_SOLANA_MERKLE_ROOT_HEX"
deploy/recovery-lab/scripts/check-artifacts
```

`reconcile-anchor` is the pass/fail boundary: the restored canonical records must reproduce the saved finalized Solana Merkle root. The lab cannot replace the real-infrastructure restore drill required for release gate 7.
