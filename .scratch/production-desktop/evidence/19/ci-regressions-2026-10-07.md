# CI regressions — 2026-10-07

Branch: `feat/pipeline-live-demo-20261006`; tested working tree after HEAD `1317f28`.
GitHub run: https://github.com/dsahakyan15/OneLayer/actions/runs/37524480443

Remote result before fixes: browser PASS; protocol FAIL; desktop FAIL.

Protocol: all four migration-digest cases failed to start PostgreSQL on Ubuntu. Native launcher used the distro default Unix socket directory although clients use loopback TCP. `ensure_postgres` now disables unused Unix sockets with `-k ''`; TCP remains bound to `127.0.0.1`. The real migration tests then passed 4/4, no skips, in 20.963 seconds. Command: `node --test --test-concurrency=1 --experimental-transform-types tests/e2e/migration-digest.test.ts`. Shell syntax validation passed.

Desktop: installed smoke rejected GTK stderr reporting the missing Adwaita SVG pixbuf loader. CI now explicitly installs `librsvg2-common` and `shared-mime-info`. The strict stderr check is retained. Remote confirmation after integration/push is still pending.

Recovery: new package originally shared the API node_modules via a local symlink. Generated its lockfile in an empty temporary package directory, then installed its own dependencies using `npm ci --ignore-scripts`: 18 packages, 0 reported vulnerabilities. `npm --prefix apps/recovery run typecheck` PASS and `npm --prefix apps/recovery test` 4/4 PASS, no skips, 8.459 seconds. CI adds the same package install, typecheck and tests. This validates the current bounded recovery tests; full-state capture/import, trusted chain binding and live writer fencing remain under independent review and are not declared complete.

No production signing keys, real devnet writes, or production deployment were used.
