# Ticket 07 continuation — migration integrity and credential expiry

Date: 2026-10-01. Base commit: `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`; shared dirty workspace, no commit or deployment. Work performed with DeepSeek v4.1 Flash subagents at max reasoning and coordinator integration. Independent review completed by Kepler (same model/effort).

## Credential compatibility and negative coverage

Migration 0016, expiry enforcement, and mandatory CLI TTL arguments already existed before this round. This round repairs tests that no longer exercised their intended invariants: the duplicate-credential fixture now supplies expiry so its rejection proves the one-live-credential unique index; provisioning/rotation HTTP fixtures now supply an explicit 30-day TTL so filesystem and unknown-commit tests reach those paths rather than failing argument validation.

New tests exercise expired credentials across independent stores/pools, expiry denial aggregation and audit, write-time revalidation, replacement by rotation, configured TTL bounds and database TTL constraints. Setting expiry to the current database timestamp and authorizing afterward tests expired timestamp rejection; it does not independently distinguish exact-clock equality from strict less-than. No constraints were weakened.

The access contract now describes the existing expiry behavior, explicit host CLI TTL, and the runtime role migration. Creating that role does not automatically change the API connection identity; deployment must configure a separate non-owner LOGIN member. No production role provisioning is claimed.

## Checks performed

- Baseline `npm --prefix apps/demo-api run typecheck`: PASS.
- Baseline `npm --prefix apps/demo-api test`: 119 PASS, zero failures/skips.
- Baseline service-principal integration: reproduced the expiry NOT NULL failure instead of the intended uniqueness rejection.
- Baseline service-principal HTTP integration: reproduced missing TTL arguments preventing the intended CLI paths.
- Subagent focused service-principal unit tests: 5 PASS, zero failures/skips.
- Subagent focused service-principal integration: 10 PASS, zero failures/skips, disposable PostgreSQL.
- Coordinator service-principal HTTP integration after fixture repairs: 2 PASS, zero failures/skips, real API processes and disposable PostgreSQL.
- Coordinator workflow-version-exclusion integration: 3 PASS, zero failures/skips.
- Coordinator publication-ambiguity integration: 3 PASS, zero failures/skips, synthetic archive/chain with disposable PostgreSQL; no live external chain or production archive attestation.

## Migration integrity implementation

The native runner verifies recorded checksums against every applied migration before applying pending SQL or fixtures. Changed/missing files and missing/unusable digests refuse startup; unknown legacy digests are not backfilled. The legacy journal may gain a nullable checksum column, but missing historical checksums still refuse startup. Operators must recover authentic historical migration evidence or recreate the synthetic database rather than silently bless current files.

Pending SQL is copied into a private per-run temporary directory, hashed there, and applied from the same snapshot. The checksum INSERT and migration execute in one PostgreSQL transaction under an advisory lock. A failed SQL statement rolls back both schema changes and the checksum row. Concurrent runners cannot clobber shared statement files; a race on one version fails on the primary key rather than applying it twice. Simultaneous runners were not directly tested.

Regression scenarios execute the real launcher/psql over temporary copies of migrations and fixtures with disposable PostgreSQL: rerun preserves application timestamps, changed/deleted migrations refuse before fixtures, legacy/malformed checksum refuses, SQL failure rolls back the new relation and journal row, retry succeeds, and temporary snapshots are removed on success/failure. The runtime initialization script is stubbed to avoid creating actual demo keys or using the application database.

CI now installs PostgreSQL before root e2e tests. The suite can still skip locally when PostgreSQL server tools are unavailable; the reported local run had zero skips. GitHub CI was not executed in this session.

Final API typecheck and full unit suite: PASS, 120 tests, zero failures/skips. Migration subagent and coordinator regression suites: 4 PASS each, zero failures/skips. `bash -n deploy/devnet-demo/native` and full `git diff --check`: PASS.

## Independent review and disposition

Kepler independently reproduced unit 120/120, store integration 10/10, HTTP integration 2/2 and migration regression 4/4, all zero skips, plus typecheck, shell syntax and diff checks. No correctness defects found in the bounded implementation. Review excluded pre-existing verifier/trust changes in the same dirty tree.

- P3 startup schema list omitted 0016: corrected the contract to include NOT NULL expiry and validated TTL CHECK.
- P3 expiry comment implied exact-clock equality: corrected the comment; the evidence already states that equality is not independently tested.
- P3 CI could skip without `pg_config`: added `libpq-dev` and a required binary preflight before root e2e; missing PostgreSQL tools now fail CI rather than silently skip.
- File-mode nit: the mounted volume reports both files as mode 777. `chmod 644` on CI YAML and deployment README returned success but modes remained 777. The tree already contained extensive mode changes before this round. No index mode or repository configuration was changed to hide filesystem behavior; mode normalization remains a filesystem limitation for a later commit.

Post-review edits affect documentation, a test comment and CI setup only; no runtime logic changed. Kepler re-read the corrections and confirmed all three P3 findings closed, with no new issues. The file-mode issue was confirmed as a fuseblk mount limitation. The coordinator verified CI prerequisite ordering and executed the required-tool shell preflight locally; no YAML parser is installed. GitHub CI execution remains unverified locally.

## Remaining acceptance

Full ticket 07 acceptance remains open, including deployment identity provisioning and service read-route wiring. No production readiness is claimed.
