# 03 — Trust policy, частичная реализация

2026-09-19, working tree поверх `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`. Execution: in-progress.

Реализованы deployment-owned policy version 1, pins genesis/program/registry/config, issuer allowlist с Ed25519, expiry/validity/revocation и минимум revision из env. Verifier и native launcher используют policy; существующий policy файл не перезаписывается автоматически. Certificate V1 не изменен.

`npm --prefix apps/verifier test`: 29 PASS; typecheck PASS; cross-language synthetic certificate E2E PASS. Unauthorized issuer/program, wrong genesis/config/owner/ledger, revoked key, future issuance, expiry, retired historical interval, malformed policy и revision ниже deployment floor проверены. Политика provisioned из синтетического seed проверена отдельным subprocess, изменение issuer/expiry не приводит к тихому перезаписыванию.

Не завершены durable anti-rollback, authenticated policy distribution, custody и local-validator account constraints acceptance. Mock chain не подтверждает live-chain exploit prevention. Тесты старого ключа относятся к заявленному issuedAt, не доказывают время подписи скомпрометированным ключом. [Общий отчет](../../../../docs/implementation-progress-2026-09-19.md).

## Continuation 2026-09-24

Commit: working tree over `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2` (uncommitted; shared tree with other agents).
Environment / OS / versions: Linux 6.8.0-106-generic, Node v24.10.0, TypeScript 5.9.3, @solana/kit 7.0.0, solana-test-validator 3.1.10 (Agave), `onchain/target/deploy/onelayer_registry.so` sha256 `db0c7203d771ed15b87fa418b810a555446fa991350f9dc7b0c2f39d36618ef9` (prebuilt, not rebuilt in this session).
Dataset ID/hash: synthetic only (fixed Ed25519 seeds 0x07/0x0b/0x21/0x22/0x31/0x32, synthetic registry ids); no production keys or PII.

Проблема и invariant:
- Anti-rollback: до изменения verifier принимал policy любой revision ≥ deployment floor (`ONELAYER_TRUST_POLICY_MIN_REVISION`). Подмена файла на старую revision (например, вернуть ключ, отозванный позже) проходила. Regression `trust-state.test.ts` «verifier restart refuses a policy rolled back below the accepted revision» до фикса падал (`actual: true` — verifier стартовал на revision 1 после принятой revision 2), после фикса проходит.
- Invariant: принятая revision/digest монотонна и durable; меньшая revision → `TRUST_POLICY_ROLLBACK`; та же revision с другим digest → `TRUST_POLICY_CONFLICT`; отсутствующий watermark → `TRUST_STATE_MISSING` (только явный bootstrap); повреждённый → `TRUST_STATE_CORRUPT` (файл не перезаписывается); нечитаемый/незаписываемый → `TRUST_STATE_UNAVAILABLE`. Expired policy не продвигает watermark.

Измененный Interface (первая итерация; env/bootstrap/state-path/watermark-формат **заменены** после review — см. «Post-review update» ниже):
- Новый `apps/verifier/src/trust-state.ts`: `loadTrustPolicy({policyFile, stateFile, minimumRevision, trustRoots?, bootstrap?})`, `enforceTrustWatermark`, `authenticatePolicyDocument`, `policyDigest` (sha256 точных байтов policy-документа), `parseTrustRootKeys`, `defaultTrustStateFile`.
- Watermark: JSON `{"format":"onelayer.trust-state.v1","revision":N,"policyDigest":"<sha256 hex>"}`, запись tmp (`wx`, 0600) → fsync → rename → fsync каталога.
- `main.ts` (startup, fail-closed = процесс не стартует): env `ONELAYER_TRUST_STATE_FILE` (default `<policy>.accepted-state.json`), `ONELAYER_TRUST_STATE_BOOTSTRAP=1` (явный первый запуск), `ONELAYER_TRUST_ROOT_KEYS=keyId:ed25519hex[,…]` (опционально; если задан — принимается только signed envelope).
- Signed envelope: `{"format":"onelayer.signed-trust-policy.v1","payloadBase64":…,"signatures":[{"rootKeyId","signatureHex"}]}`, Ed25519 над `"onelayer.trust-policy.v1\0" || payload`; digest считается по payload, поэтому replay старого подписанного документа ловится watermark.
- `scripts/create-demo-trust-policy.ts` (вызывается `deploy/devnet-demo/native`) теперь явно bootstrap-ит watermark по default-пути; существующий watermark применяется, а не сбрасывается.
- Новый opt-in script `npm --prefix apps/verifier run test:local-chain` (`tests/local-chain.harness.ts`; не входит в `npm test`, потому что требует validator и ~50 s).
- Certificate V1 encoding, spec/*, onchain/, migrations не изменены.

Commands and results:
- Baseline до изменений: `npm --prefix apps/verifier test` → 30 PASS; typecheck PASS.
- Red: `node --test --experimental-strip-types apps/verifier/tests/trust-state.test.ts` → 1 FAIL (rollback принят).
- `npm --prefix apps/verifier test` → **35 PASS, 0 fail, 0 skipped**.
- `npm --prefix apps/verifier run typecheck` → PASS.
- `npm --prefix apps/verifier run test:local-chain` → **1 PASS** (48.5 s; 4 транзакции finalized за 13.7–14.9 s каждая на локальном validator).
- `node --test --experimental-strip-types --test-name-pattern="native verifier" tests/e2e/native-bind.test.ts` → **FAIL: `TRUST_STATE_MISSING`** (ожидаемо fail-closed; см. ограничения — fixture не мой scope).

Negative cases (новые):
- Watermark (`trust-state.test.ts`): отсутствие без bootstrap; rollback revision 3→2; rollback при `bootstrap` (bootstrap не сбрасывает); same-revision substitution (revoked→unrevoked); пять вариантов повреждённого state (пустой, обрезанный JSON, `null`, revision 0, лишнее поле) — файл сохранён без изменений; state-путь — каталог (EISDIR); state в несуществующем каталоге (запись невозможна); отсутствующий policy file; expired policy не создаёт watermark; после продвижения нет временных файлов.
- Authenticated distribution: plain policy при закреплённых roots; подпись незакреплённым ключом; подпись чужим ключом с keyId закреплённого root; подмена payload; пустой набор roots; replay старой корректно подписанной revision → ROLLBACK; второй подписанный документ той же revision → CONFLICT.
- Rotation lifecycle (`verify.test.ts`, через durable store rev1→rev2→rev3): исторический сертификат старого ключа (issuedAt внутри интервала) VERIFIED после ротации; ключ-замена в своём интервале VERIFIED; старый ключ с issuedAt после retirement → `ISSUER_TIME_INVALID`; ключ-замена с issuedAt до validFrom → `ISSUER_TIME_INVALID`; rev3 отзывает старый ключ → `ISSUER_REVOKED`, замена остаётся VERIFIED; попытка вернуть rev2 (реактивировать скомпрометированный ключ) → `TRUST_POLICY_ROLLBACK`.

Real integration (local chain harness, synthetic):
- solana-test-validator + собранный `onelayer_registry.so` на `6A2L…czEo`; реальные `initialize_registry` + `grant_operator` + `create_ledger_segment` + `publish_anchor` для двух registry; проверка через `SolanaRpcChainReader` (finalized account/transaction reads).
- PASS: trusted certificate → `VERIFIED` (slot = slot anchor-транзакции).
- Rejected: wrong genesis pin → `CLUSTER_UNTRUSTED`; policy pinned к реальному config другого registry → `REGISTRY_CONFIG_UNTRUSTED`; реальный anchor ledger-а другого registry → `LEDGER_REGISTRY_MISMATCH`; незакреплённый issuer над реальным anchor → `ISSUER_UNTRUSTED`; незакреплённый program id → `PROGRAM_UNTRUSTED`; policy доверяет program без program-owned config → `REGISTRY_STATUS_UNAVAILABLE`; закреплённый registry без config account → `REGISTRY_STATUS_UNAVAILABLE`.
- Ручное наблюдение при отладке harness (harness эти коды **не проверяет** assert-ами): программа вернула `WrongLedgerDay`, когда `day_utc` был передан как дни от epoch (в исходнике `utc_day` = YYYYMMDD), и `DeclaredProgramIdMismatch` при загрузке того же `.so` под другим program id.

Migration / rollback implications:
- Существующие deployments без watermark не стартуют, пока оператор не выполнит явный bootstrap (`ONELAYER_TRUST_STATE_BOOTSTRAP=1` один раз) или не запустит обновлённый `create-demo-trust-policy.ts`. Это намеренный fail-closed.
- Легальная ротация = новая policy с большей revision; тот же номер с другим содержимым отвергается (даже переформатирование файла). Откат verifier-кода на предыдущую версию игнорирует watermark (защиту даёт только новый код).

Ограничения и что НЕ проверено:
- ~~tests/e2e/native-bind.test.ts падает с `TRUST_STATE_MISSING`~~ — исправлено: координатор добавил bootstrap, после review fixture обновлена под новый механизм (см. ниже), 3/3 PASS.
- Удаление watermark + явный bootstrap (включая повторный запуск demo provisioning script) откатывает защиту до deployment floor. Защита от атакующего с правом записи в каталог verifier state отсутствует; нужен внешний монотонный источник (TPM/HSM counter, подписанный watermark или floor, выдаваемый trust root).
- Authenticated distribution реализована в verifier, но **не включена по умолчанию** (demo launcher использует unsigned deployment-owned policy); нет инструмента подписи policy, custody trust-root ключа, ceremony, ротации/отзыва самого trust root, threshold (сейчас достаточно 1 подписи из закреплённых). Policy загружается только при старте (нет hot reload); конкурентные процессы с одним state файлом не сериализуются lock-ом.
- Тесты ротации опираются на заявленный `issuedAt`: подпись скомпрометированным ключом с backdated `issuedAt` внутри легального интервала не отличима (нужен trusted timestamp/anchor-slot binding — отдельное решение).
- Local chain: foreign **deployed** program не проверен (требует отдельной сборки с другим `declare_id`); owner-mismatch config account (аккаунт по PDA, но другого owner) не сконструирован; devnet/mainnet не проверялись; `.so` не пересобирался в этой сессии.
- **Находка вне scope (demo-api):** on-chain `utc_day` = YYYYMMDD (`onchain/programs/onelayer-registry/src/lib.rs` `utc_day`, тест `20260731`), а `apps/demo-api/src/admin.ts:366` и `publication-worker.ts:306` вычисляют `dayUtc = floor(ms/86_400_000)` (дни от epoch). Против этого `.so` такие `create_ledger_segment`/`publish_anchor` дадут `WrongLedgerDay` и неверный segment PDA. Требует проверки владельцем demo-api/onchain (возможно, задеплоенный на devnet binary отличается).

Reviewer / findings / disposition: см. «Review findings / disposition» ниже (независимый review 2026-09-24, blocker нет).
Следующий ticket и передаваемые contracts: watermark/envelope formats и env выше; native-bind fixture fix (владелец tests/e2e); решение по custody trust-root и включению signed policy по умолчанию (ticket 16 / владелец); demo-api dayUtc (владелец demo-api).

## Post-review update 2026-09-24

Изменённый Interface (действующий):
- Env verifier (`trustOptionsFromEnv`, любая неоднозначность → `TRUST_CONFIG_INVALID`, процесс не стартует):
  - режим задаётся явно, ровно один из: `ONELAYER_TRUST_ROOT_KEYS=keyId:ed25519hex[,…]` (signed) или `ONELAYER_TRUST_POLICY_UNSIGNED=1` (явный opt-in, demo). Неявного режима по умолчанию нет.
  - `ONELAYER_TRUST_DEPLOYMENT=<genesisHash>/<registryId>/<programIdHex>` обязателен в signed-режиме (в unsigned проверяется, если задан); несовпадение с payload → `TRUST_POLICY_DEPLOYMENT_MISMATCH`.
  - `ONELAYER_TRUST_STATE_FILE` обязателен (пути по умолчанию нет).
  - `ONELAYER_TRUST_STATE_BOOTSTRAP=<sha256 hex документа policy>`: создаёт отсутствующий watermark только для документа с этим digest (иначе `TRUST_STATE_BOOTSTRAP_MISMATCH`); при существующем watermark не действует.
  - `ONELAYER_TRUST_POLICY_MIN_REVISION` строго `^[1-9][0-9]*$`, safe integer.
- Watermark: `{"format":"onelayer.trust-state.v1","revision","policyDigest","authenticated"}`. Формат первой итерации (без `authenticated`) читается как `TRUST_STATE_CORRUPT` (он не выпускался). Правила: signed был принят, а сейчас unsigned → `TRUST_POLICY_DOWNGRADE`. Unsigned→signed того же документа фиксируется как `authenticated:true`. Шаг revision больше `MAX_REVISION_STEP=1000` → `TRUST_POLICY_REVISION_JUMP`.
- Расположение state (`assertPrivateStateLocation`, → `TRUST_STATE_LOCATION_UNSAFE`): каталог state ≠ каталог policy (по realpath); каталог и файл проверяются через `lstat` (не symlink, каталог — directory, файл — regular); не group/world-writable; владелец — текущий uid.
- Эксклюзивный lock `<state>.lock` (`O_CREAT|O_EXCL`, 0600) вокруг read→compare→write. Ожидание до 5 s, затем `TRUST_STATE_LOCKED`. Lock, оставшийся после crash, требует ручного удаления (fail-closed).
- Signed envelope: нераспознанные или испорченные записи подписей пропускаются; достаточно одной валидной подписи закреплённого root.
- `scripts/create-demo-trust-policy.ts <issuer seed> <policy> <state>` — явная одноразовая bootstrap-команда unsigned demo, digest-pinned. Новая policy получает revision = accepted watermark + 1. Шаг ротации demo: убрать истёкший policy-файл (`mv verifier-trust-policy.json verifier-trust-policy.json.expired`) и снова выполнить `deploy/devnet-demo/native start`.
- Вне verifier (разрешено координатором из-за смены bootstrap):
  - `deploy/devnet-demo/native`: state = `${XDG_STATE_HOME:-$HOME/.local/state}/onelayer-devnet-demo/verifier-trust/accepted.json` (volume репозитория world-writable, поэтому state вне него); передаётся скрипту; verifier получает `ONELAYER_TRUST_POLICY_UNSIGNED=1` и `ONELAYER_TRUST_STATE_FILE`.
  - `tests/e2e/native-bind.test.ts`: приватный `verifier-state/` (0700), `ONELAYER_TRUST_POLICY_UNSIGNED=1`, bootstrap = sha256 policy.
  - `deploy/devnet-demo/README.md`: trust-раздел обновлён координатором, затем мной во втором раунде (см. ниже).

Commands and results (после review):
- `npm --prefix apps/verifier test` → **39 PASS**, 0 fail, 0 skipped.
- `npm --prefix apps/verifier run typecheck` → PASS.
- `npm --prefix apps/verifier run test:local-chain` → **1 PASS** (43.7 s).
- `node --test --experimental-transform-types tests/e2e/native-bind.test.ts` → **3 PASS** (demo-api, verifier, web).
- Проверка чувствительности тестов (временная мутация, после неё исходник восстановлен и suite перезапущен):
  - lock отключён → race-тест FAIL в 3/3 запусках;
  - проверка deployment pin отключена → тест signed distribution FAIL.
- Live-запуск `deploy/devnet-demo/native start` не выполнялся (bash -n PASS).

Negative cases (новые после review): signed devnet-envelope большей revision под тем же root (genesis / registry / program) → `DEPLOYMENT_MISMATCH`; signed→unsigned тех же payload-байтов → `DOWNGRADE`; state в каталоге policy, через symlink на каталог policy, state-файл symlink, файл 0666, каталог 0777 → `LOCATION_UNSAFE`; bootstrap с чужим digest → `BOOTSTRAP_MISMATCH`; revision +1001 и `2^53-1` → `REVISION_JUMP` (+1000 принимается); 30 раундов гонки rev3 ∥ rev2 → watermark всегда 3; испорченные записи подписей рядом с валидной → принято; env: нет режима, оба режима, `UNSIGNED=true`, signed без deployment, пустые roots, `MIN_REVISION` `01`/`1e3`/`0`, `BOOTSTRAP=1`, пустой state path, deployment pin без registry → config error; demo-ротация после истечения → revision 2.

Остаточный риск (честно):
- **Unsigned-режим**: anti-rollback защищает только от случайного отката (восстановление policy из backup, ошибка оператора, повторный деплой старого артефакта). Атакующего с правом записи в policy не останавливает: он пишет policy с большей revision. Атакующий с правами uid verifier может также удалить или переписать state. Отдельный приватный каталог отсекает только того, у кого есть запись в каталог policy, но нет прав uid verifier.
- **Signed-режим**: защищает от подмены и replay между deployments при условии, что trust-root ключ не скомпрометирован. Удаление state и повторный digest-pinned bootstrap остаются операторским действием: откат возможен только к документу с явно указанным digest. Для защиты от root/uid-атакующего нужен внешний монотонный источник (TPM/HSM counter или floor, выданный trust root) — не реализовано.
- Lock не защищает от процесса, игнорирующего протокол, и от сетевых FS без атомарного `O_EXCL`. Hot reload отсутствует. Custody, ceremony, ротация и threshold trust-root ключей не реализованы (ticket 16).

## Review findings / disposition

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | major | Signed payload не привязан к deployment | **Fixed.** `ONELAYER_TRUST_DEPLOYMENT` обязателен в signed-режиме, сверяется с genesis/registry/program из подписанного payload → `TRUST_POLICY_DEPLOYMENT_MISMATCH`. Negative test на все три поля. Отдельное поле `deploymentId` в payload не вводилось: формат policy strict и уже содержит эти поля (config PDA пинится policy и проверяется on-chain). |
| 2 | major | State по умолчанию рядом с policy | **Частично в раунде 1** (повторное review: проверка слишком узкая), доведено в раунде 2 (N1). Пути по умолчанию нет (во всех режимах). Проверки: отдельный каталог (realpath), `lstat` без symlink, не group/world-writable, текущий uid. Остаточный риск описан выше. |
| 3 | major | Тихий переход signed→unsigned | **Fixed.** `authenticated` в watermark, `TRUST_POLICY_DOWNGRADE`; unsigned только по явному `ONELAYER_TRUST_POLICY_UNSIGNED=1`, иначе config error. |
| 4 | minor | Гонка процессов откатывает watermark | **Fixed.** O_EXCL lock вокруг read→compare→write; тест на 30 раундов, красный без lock (3/3). |
| 5 | minor | `BOOTSTRAP=1` остаётся в env | **Частично в раунде 1** (demo bootstrap не был одноразовым), доведено в раунде 2 (N3). Значение — sha256 документа; при существующем watermark игнорируется. Demo bootstrap — отдельная команда (provisioning script). |
| 6 | minor | Demo всегда revision 1 | **Fixed.** revision = watermark + 1; шаг ротации задокументирован в скрипте и здесь; тест ротации. |
| 7 | minor | Исчерпание revision | **Fixed** (первый bootstrap ограничен в раунде 2). `MAX_REVISION_STEP=1000` относительно watermark (оба режима). Первый bootstrap ограничен только digest pinning. |
| 8 | minor | Одна плохая подпись отменяет валидные | **Fixed.** Нераспознанные записи пропускаются; тест. |
| 9 | minor | Нестрогий `MIN_REVISION` | **Fixed.** `^[1-9][0-9]*$` + safe integer → `TRUST_CONFIG_INVALID`. |
| E | evidence | Формулировки WrongLedgerDay/DeclaredProgramIdMismatch; риск unsigned | **Fixed.** Помечено как ручное наблюдение; остаточный риск описан. |

Execution: `in-review`.

## Second review round 2026-09-24

Изменения:
- **N1 — расположение state.**
  - Путь каталога state должен совпадать со своим realpath (без symlink в любом компоненте).
  - Каталог state не может совпадать с каталогом policy, быть вложенным в него или содержать его. Сравнение идёт по realpath каталога policy и по realpath самого policy-файла.
  - Все предки до `/` принадлежат root или пользователю verifier. Group/world-writable предок допустим только со sticky bit.
  - Сам каталог state: владелец — пользователь verifier, без group/world write.
  - Watermark читается через fd, открытый с `O_RDONLY|O_NOFOLLOW`, и проверяется по `fstat` (regular file, владелец, права).
  - Temp-файл и lock создаются с `O_CREAT|O_EXCL|O_NOFOLLOW`; fsync каталога идёт через `O_DIRECTORY|O_NOFOLLOW`.
  - Demo script проверяет расположение state до создания policy.
- **N2 — digest.** Одно определение для обоих режимов: sha256 точных байтов policy JSON-документа (в unsigned — файл, в signed — декодированный `payloadBase64`). Определение закреплено в коде (`policyDigest`) и в README с командами. `TRUST_STATE_BOOTSTRAP_MISMATCH` больше не раскрывает digest.
- **N3 — одноразовый demo bootstrap.** Bootstrap digest передаётся только в том запуске скрипта, который сам создал policy. Если watermark пропал при сохранившейся policy — fail-closed: ничего не меняется, в сообщении указаны варианты (восстановить watermark или осознанно переместить policy). README приведён в соответствие.
- **N4 — stale lock.** Автоочистка сознательно не реализована: pid reuse и lock с другого хоста делают её небезопасной. Вместо неё `TRUST_STATE_LOCKED` с диагностикой (pid, host, «NOT running») и процедура в README: убедиться, что state никто не использует, удалить `<state>.lock`. Lock теперь содержит `pid hostname`. Таймаут настраивается в API (`lockTimeoutMs`; в env не выносится).
- **N5 — переход unsigned→signed** описан в README и здесь: либо byte-identical payload той же revision, либо большая revision (≤ +1000). Unsigned watermark переносится как floor; после signed unsigned отвергается. Тест на rev+1, same-revision conflict и rollback ниже floor.
- **N6 — каноничный deployment pin:** ровно 3 компонента; genesis — base58 (32–44); registryId `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` без `..`; program — lowercase hex 64. Пробелы, пустые компоненты, лишние `/`, uppercase hex, небазовый genesis отвергаются.
- **Revision (finding 7):** первый bootstrap ограничен `revision ≤ MIN_REVISION + 1000`.
- **Вне verifier:**
  - `tests/e2e/native-bind.test.ts`: state в отдельном mkdtemp-каталоге, так как прежний `verifier-state/` лежал внутри каталога policy и теперь корректно отвергается.
  - `deploy/devnet-demo/README.md`: trust-раздел (bootstrap/digest, требования к state, ротация, потеря watermark, unsigned→signed, stale lock).
  - `deploy/devnet-demo/native` в этом раунде не менялся: путь XDG проходит новые проверки, предки на этой машине — `/` root 755, `/home` root 755, `$HOME` davit 750, `~/.local/state` 700.

Commands and results (раунд 2):
- `npm --prefix apps/verifier test` → **42 PASS**, 0 fail, 0 skipped.
- `npm --prefix apps/verifier run typecheck` → PASS.
- `node --test --experimental-transform-types tests/e2e/native-bind.test.ts` → **3 PASS**.
- `npm --prefix apps/verifier run test:local-chain` в раунде 2 **не перезапускался**: код, который он проверяет (`verify.ts`, `solana-rpc.ts`), не менялся. Последний прогон — 1 PASS (раунд 1). На машине работали validators других агентов.

Negative cases (раунд 2):
- Четыре probe-случая ревьюера: state внутри каталога policy (и policy внутри каталога state); предок 0777 без sticky (с 1777 — принят); symlink в предке пути state; policy-файл — symlink на файл в каталоге state.
- Symlink на state-файл отвергается через `O_NOFOLLOW`.
- Bootstrap revision 1002 при floor 1 отвергается (1001 — принят).
- Stale lock с мёртвым pid → `TRUST_STATE_LOCKED … NOT running`, watermark не тронут; после удаления lock — успех.
- Сообщение bootstrap mismatch не содержит digest.
- 9 неканоничных deployment pin.
- Demo: пропавший watermark при сохранённой policy → ошибка, watermark не пересоздан, policy не изменена; после восстановления — успех.
- unsigned→signed: та же revision с другим payload → CONFLICT; revision ниже floor → ROLLBACK; rev+1 → принят, `authenticated:true`.

Остаточный риск (раунд 2):
- rename и fsync temp-файла идут по имени, так как в Node нет `renameat`/`openat`. TOCTOU между проверкой предков и операциями остаётся. Его закрывает то, что ни один компонент пути не доступен на запись другим пользователям (кроме sticky-каталогов, где чужие записи нельзя подменить). Процесс с uid verifier или root этим не ограничивается.
- Проверка владельцев пропускается, если `process.getuid` недоступен (не-POSIX).
- `/proc`-подобные и сетевые FS без атомарного `O_EXCL`/rename не поддерживаются.
- Остаток по unsigned/signed режимам и trust-root custody — как в «Post-review update».

## Review findings / disposition (round 2)

| # | Finding | Disposition |
|---|---|---|
| N1 | Узкая проверка location, TOCTOU | **Fixed в пределах Node API**: disjoint по realpath (включая policy-файл), проверка предков, запрет symlink в пути, `O_NOFOLLOW` + `fstat`. TOCTOU на rename по имени — документированный остаток. Тесты на все 4 probe. |
| N2 | Digest bootstrap vs README | **Fixed**: одно определение (policy JSON bytes) в коде и README; digest не печатается. |
| N3 | Demo bootstrap не одноразовый | **Fixed**: bootstrap только при создании policy этим запуском; пропавший watermark → fail-closed с инструкцией. |
| N4 | Stale lock | **Documented + diagnostic** (автоочистка отклонена как небезопасная); тест. |
| N5 | Переход unsigned→signed | **Documented + tested.** |
| N6 | Неканоничный deployment pin | **Fixed**, тесты. |
| 7 | Первый bootstrap без лимита | **Fixed**: `≤ MIN_REVISION + 1000`, тест. |
| E | Evidence | **Fixed**: убрано «README не обновлён», 2 и 5 помечены как частично закрытые в раунде 1, добавлен этот раздел. |

Execution: `in-review` до подтверждения раунда 2.


## Continuation 2026-09-28 — root set, rotations, external floor

Commit: working tree поверх `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2` (не закоммичено; общий tree с другими агентами).
Environment / OS / versions: Linux 6.8.0-106-generic, Node v24.10.0, TypeScript 5.9.3, solana-test-validator 3.1.10 (Agave), `onchain/target/deploy/onelayer_registry.so` sha256 `db0c7203d771ed15b87fa418b810a555446fa991350f9dc7b0c2f39d36618ef9` (не пересобирался).
Dataset: только synthetic (Ed25519 seeds 0x21–0xb2, synthetic registry); production ключей и PII нет.

Исходное состояние: после раунда 2 (2026-09-24, 42 PASS) в `apps/verifier/src` появился незадокументированный и незавершённый рефакторинг: `TrustMode.signed` = `{anchor: RootSet, rotationsFile?, deployment, floor: TrustFloorSource, floorMaxAgeMs?}` вместо `trustRoots`, новые `trust-envelope.ts` (threshold-подписанные envelopes трёх видов с доменным разделением, цепочка ротаций root set) и `trust-floor.ts` (внешний подписанный floor с ограниченной свежестью), watermark v2 (`rootEpoch`, `rootSetDigest`). Тесты не обновлены: typecheck FAIL (4 ошибки `trustRoots` в `tests/trust-state.test.ts`), `npm test` 40/44. Изменения `verify.ts`/`http-adapters.ts` того же времени (ADR-0008 `incidentBlocks`, `resolutionStatus`/`blocking`) к trust-рефакторингу не относятся и не трогались.

Восстановленное намерение (по коду) и принятые решения:
- Закрыть открытые пункты 03: «внешний монотонный источник против удаления state» → signed floor `{deploymentId, minimumPolicyRevision, minimumRootEpoch, issuedAt, expiresAt, nonce}`, подписанный threshold **текущего** root set; «backdated `issuedAt` скомпрометированным ключом» → отзыв ключа (`revoked` отвергает любую подпись, включая «историческую») теперь нельзя откатить даже удалением watermark (floor). Ротация самих trust-root ключей и k-of-n threshold — часть того же рефакторинга.
- Решение 1 (fail-closed): signed режим без floor не существует; `ONELAYER_TRUST_ROOT_THRESHOLD` и `ONELAYER_TRUST_FLOOR_FILE` обязательны, значений по умолчанию нет; signed-only переменные в unsigned режиме → `TRUST_CONFIG_INVALID` (не игнорируются). Сохранено как в рефакторинге.
- Решение 2 (добавлено): anchor можно перезакрепить на epoch N (`ONELAYER_TRUST_ROOT_EPOCH`, по умолчанию 1). Без этого компрометация threshold ключей epoch 1 необратима: атакующий обрезает/подделывает цепочку и сам подписывает floor. Записи цепочки с epoch ≤ N отвергаются (`TRUST_ROOT_ROTATION_INVALID`), а не пропускаются.
- Решение 3 (исправлено): `rootSetDigest` сортировал ключи через `localeCompare` (зависит от ICU/locale хоста → ложный `TRUST_ROOT_CONFLICT`); теперь порядок code units.
- Решение 4 (исправлено): лимит первого bootstrap `≤ max(MIN_REVISION, floor.minimumPolicyRevision) + 1000` — иначе при высоком floor легальный bootstrap был невозможен.
- Решение 5 (не реализовано, требует владельца): привязка validity issuer-ключа ко времени блока anchor (сертификат подписывается после anchor-транзакции: `admin.ts` issuance берёт `intent.signature`/`anchorSlot`) закрыла бы backdating для **неотозванного** retired-ключа. Это меняет `ChainReader`/`ObservedAnchor` (нужен `blockTime`), который реализуют mocks в `apps/demo-api/tests/admin-batch.test.ts` (чужой scope), и семантику verification → нужно versioned решение. Предложение: `ObservedAnchor.blockTime` (обязательный, `SolanaRpcChainReader` берёт `transaction.blockTime`, null → fail-closed), правило `issuer.validFrom ≤ blockTime < issuer.validUntil` и `issuedAt ≥ blockTime − skew`.

Изменённый Interface (действующий для signed режима; unsigned и native demo не изменились):
- env: `ONELAYER_TRUST_ROOT_KEYS`, `ONELAYER_TRUST_ROOT_THRESHOLD` (обяз.), `ONELAYER_TRUST_ROOT_EPOCH` (опц., default 1), `ONELAYER_TRUST_ROOT_ROTATIONS_FILE` (опц.; указан, но отсутствует → `TRUST_ROOT_UNAVAILABLE`), `ONELAYER_TRUST_FLOOR_FILE` (обяз.), `ONELAYER_TRUST_FLOOR_MAX_AGE_SECONDS` (опц., default 86400, ≤ 30 дней), `ONELAYER_TRUST_DEPLOYMENT` (обяз.).
- envelopes `onelayer.signed-trust-{policy,root-set,floor}.v1`, домены `onelayer.trust-{policy,root-set,floor}.v1\0`; root set payload `onelayer.trust-root-set.v1` с `deploymentId`, epoch +1.
- watermark `onelayer.trust-state.v2` (+`rootEpoch`, `rootSetDigest`); v1 читается и переписывается в v2 при следующем изменении.
- новые коды: `TRUST_ROOT_ROLLBACK`, `TRUST_ROOT_CONFLICT`, `TRUST_ROOT_ROTATION_INVALID`, `TRUST_ROOT_UNAVAILABLE`, `TRUST_FLOOR_{UNAVAILABLE,INVALID,SIGNATURE_INVALID,DEPLOYMENT_MISMATCH,STALE,NOT_YET_VALID,REPLAYED}`.
- `deploy/devnet-demo/README.md`: trust-раздел дополнен signed-режимом (env, floor, rotations, re-pin, watermark v2, лимит bootstrap). `deploy/devnet-demo/native`, `tests/e2e/native-bind.test.ts`, `scripts/create-demo-trust-policy.ts` не менялись (используют unsigned режим, контракт которого тот же).

Commands and results:
- До изменений: `npm --prefix apps/verifier run typecheck` → FAIL (4× TS2353/TS2322 `trustRoots`); `npm --prefix apps/verifier test` → 40 pass / 4 fail.
- `npm --prefix apps/verifier run typecheck` → PASS.
- `npm --prefix apps/verifier test` → **53 PASS**, 0 fail, 0 skipped (trust-state: 20).
- `npm --prefix apps/verifier run test:local-chain` → **1 PASS** (41.8 s).
- `node --test --experimental-transform-types tests/e2e/native-bind.test.ts` → первый прогон 2 PASS / 1 FAIL (`built web startup … mvp-web startup timed out` — web, не trust; машина нагружена параллельными агентами); изолированно этот тест PASS; повторный прогон всего файла → **3 PASS**. Записано как flaky по окружению, не как регрессия.
- Чувствительность тестов (временные мутации, исходники восстановлены и сверены `cmp`): без проверки floor revision → 2 FAIL; без root-epoch rollback в watermark → 1 FAIL; threshold → 1 → 2 FAIL; без проверки expiry floor → 2 FAIL; без deployment binding ротаций → 1 FAIL.

Negative cases (новые, `tests/trust-state.test.ts`, через `loadTrustPolicy`/`trustOptionsFromEnv`/процесс `main.ts`):
- Чужой root: policy, floor и rotation, подписанные незакреплённым ключом или ключом с чужим `keyId` → `*_SIGNATURE_INVALID`/`ROTATION_INVALID`; пустой anchor → `TRUST_ROOT_INVALID`.
- Threshold 2-of-3: одна подпись, одна подпись дважды, валидная + чужая → отказ; две различные → принято.
- Ротация: подпись ниже threshold, для другого deployment, пропуск epoch, повтор epoch, threshold > n, мусорная запись → `TRUST_ROOT_ROTATION_INVALID`; после ротации старый set не может подписать ни policy, ни floor.
- Откат ротации: обрезанная цепочка при watermark epoch 2 → `TRUST_ROOT_ROLLBACK`; fork epoch 2 (другой set) → `TRUST_ROOT_CONFLICT`; удалённый watermark + обрезанная цепочка → floor нового set не проверяется (`TRUST_FLOOR_SIGNATURE_INVALID`), floor старого set с `minimumRootEpoch 2` → `TRUST_ROOT_ROLLBACK … external floor`; watermark не создаётся.
- Перезакреплённый anchor: подделанная цепочка/floor/policy от скомпрометированного ключа epoch 1 → отказ на каждом шаге; легальный set epoch 2 → принят.
- Floor: отсутствует, не JSON, без envelope, чужой подписант, истёк, срок > max age, выпущен в будущем, другой deployment, epoch 0, issuedAt ≥ expiresAt, policy ниже floor, root epoch ниже floor; challenge-bound источник с чужим nonce → `TRUST_FLOOR_REPLAYED`; источник недоступен → `TRUST_FLOOR_UNAVAILABLE`; меньший pinned max age → `STALE`. Во всех случаях watermark не записан.
- Откат state при наличии floor / отозванный ключ / backdated `issuedAt`: rev2 отзывает issuer, floor поднят до 2; сертификат с `issuedAt` 2021 (внутри прежнего интервала ключа) → `ISSUER_REVOKED` (под rev1 был бы принят); удаление watermark + bootstrap rev1 → `TRUST_POLICY_ROLLBACK … external floor 2`; восстановление bootstrap-ом на rev2 проходит.
- Downgrade signed→unsigned → `TRUST_POLICY_DOWNGRADE` (сохранено); unsigned→signed переход пишет v2 с `rootEpoch 1`.
- Watermark v2: несогласованные `authenticated`/`rootEpoch`/`rootSetDigest`, v1-format с v2-полями → `TRUST_STATE_CORRUPT`; v1 мигрирует.
- Env: 18 некорректных signed/unsigned комбинаций (нет threshold, threshold 0/02/>n, нет/пустой floor, max age 0 / > 30 дней, пустой rotations, epoch 0/1.5, дубликат keyId/ключа, signed-only переменные в unsigned).
- Процесс `main.ts` в signed режиме: старт с ротацией и свежим floor → listening; истёкший floor → `TRUST_FLOOR_STALE`; обрезанная цепочка → `TRUST_FLOOR_SIGNATURE_INVALID`; удалённый floor → `TRUST_FLOOR_UNAVAILABLE`.

Ограничения и что НЕ проверено:
- Floor в env — только файл (time-bounded, без challenge): в пределах `max age` можно воспроизвести ещё не истёкший старый floor. Challenge-bound источник есть как интерфейс и lab adapter, production floor service / HSM counter не реализованы (ticket 16). Floor и policy проверяются только при старте; hot reload нет.
- Unsigned режим (native demo) внешнего floor не имеет: остаток риска как в раундах 1–2.
- Компрометация threshold текущего root set до ротации не обнаруживается; восстановление — re-pin anchor оператором. Custody, ceremony, инструмент подписи — ticket 16.
- Backdated `issuedAt` неотозванным retired ключом не закрыт (решение 5).
- Live-запуск `deploy/devnet-demo/native start` не выполнялся; devnet/mainnet не проверялись; foreign deployed program — как в раунде 1.
