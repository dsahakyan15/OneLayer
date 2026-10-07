# Clean validation of monitor and protected audit modules

Coordinator, 2026-10-07, Linux Mint 22.1 x86_64, Node 24.10.0,
PostgreSQL 17.10, pinned Agave 3.1.10. Module implementation by DeepSeek
V4.1 Flash; two prior independent MiMo V2.6 Pro review rounds accepted this
module boundary. Full pipeline integration remains open.

Validated code tree: `4cbd60d4038da7aba7447a0a9b34d7108978f97c` (before this
evidence file). It consists of committed publication baseline `db5bf24`, Rust
monitor/audit modules and `0026_monitor_audit_evidence.sql`. It excludes ongoing
GUI, recovery, API audit hooks/routes and native deployment edits. A clean Git
archive was extracted onto DATA. Installed third-party Node dependencies were
reused through symlinks; all application source came from the exported tree.

Commands:

```sh
CARGO_TARGET_DIR=<cache>/cargo-target cargo test --locked -p onelayer-monitor -p onelayer-audit
CARGO_TARGET_DIR=<cache>/cargo-target ONELAYER_MONITOR_BIN=<cache>/cargo-target/debug/onelayer-monitor ONELAYER_SBF_CACHE_DIR=<cache>/sbf-cache node --test --experimental-transform-types apps/monitor/tests/e2e/monitor-runtime.test.ts
```

- Rust: **46 passed**, zero failed/ignored (monitor 15, audit 31).
- Actual monitor process, disposable PostgreSQL and local validator: **7 passed**,
  zero failed/skipped. A clean finalized batch verified; monitor credentials
  could not write; all **20 injected tamper cases** were detected out of process;
  faulty-builder cursor gap detected; journal-tail truncation and evidence-floor
  deletion refused by verify/start commands.
- Detection samples: min 356 ms, median 375 ms, **p95 446 ms**, max 1724 ms,
  sample count 20, polling interval 300 ms. Total test duration approximately
  209 seconds. These measurements are specific to this synthetic workload.
- Program ELF SHA256:
  `db0c7203d771ed15b87fa418b810a555446fa991350f9dc7b0c2f39d36618ef9`.
- Finalized batch 1 Merkle root:
  `2cc914b2dbf5e08cae08abf59d3cc9a823962f177bb344277303f904e037909e`.

Logs retained under `/tmp/onelayer-orchestration-20261006/`:
`monitor-audit-clean-tests.log`, `monitor-clean-e2e.log`.

This commit provides the independently reviewed module boundary. It does not
close ticket 13's complete transaction-local critical-event matrix, authenticated
API/desktop evidence routes, native service integration, installed release or
production separate-host/identity provisioning. The retained floor protects
against local tail rollback; simultaneous loss/forgery of journal and floor needs
an external trust anchor. Same-host synthetic tests do not establish that anchor.
