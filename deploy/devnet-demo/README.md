# OneLayer synthetic devnet demo

Native demo для локальной проверки MVP: PostgreSQL 17, Node-сервисы, Solana
devnet и loopback-порты. Все данные синтетические, ключи создаются в tmpfs,
production credentials не используются.

## Запуск

Установите PostgreSQL 17 и зависимости приложений:

```bash
brew install postgresql@17
npm --prefix apps/demo-api ci
npm --prefix apps/verifier ci
npm --prefix apps/mvp-web ci
npm --prefix packages/onchain-client ci
```

Запустите MVP:

```bash
./deploy/devnet-demo/native start
```

Панели доступны по адресам:

- Admin: <http://127.0.0.1:8091/admin>
- OneLayer: <http://127.0.0.1:8091/verify>
- demo-api health: <http://127.0.0.1:8090/v1/health>
- verifier health: <http://127.0.0.1:8080/v1/health>

Демо-учётные данные находятся в
`/dev/shm/onelayer-devnet-demo/admin-credentials.json`.

## Управление native runtime

```bash
./deploy/devnet-demo/native status
./deploy/devnet-demo/native logs
./deploy/devnet-demo/native restart
./deploy/devnet-demo/native stop
```

Локальная база и логи находятся в игнорируемом каталоге
`deploy/devnet-demo/.runtime/native/`. База слушает только `127.0.0.1:55432`,
а веб и API — только loopback-порты `8091`, `8090` и `8080`.

При запуске runner сверяет SHA-256 файлов уже применённых миграций с журналом
`schema_migration` до применения новых миграций и fixture. Изменённый или
отсутствующий файл останавливает запуск. Восстановите исходный применённый файл,
а изменение схемы оформите следующей миграцией; удаление записи журнала не
восстанавливает соответствие схемы файлам. SQL новой миграции и запись её
checksum фиксируются одной транзакцией.

## Граница публикации в devnet

Подготовка программы и её approval digest выполняются отдельно:

```bash
cd onchain && NO_DNA=1 anchor build && cd ..
./deploy/devnet-demo/scripts/initialize-runtime
./deploy/devnet-demo/scripts/program-deploy plan
```

Команда `plan` ничего не публикует. Применение требует явно переданного
`ONELAYER_DEVNET_DEPLOY_APPROVED`, а публикация реестра — отдельного
`ONELAYER_DEVNET_TX_APPROVED`. Для обычной проверки UI запуск в devnet не
нужен: native MVP использует синтетическую базу и заранее подготовленные
данные.

## Браузерные проверки

Детерминированный E2E запускается отдельно и не требует сети или SOL:

```bash
npm --prefix tests/e2e-web test
```

Для проверки уже подготовленного native devnet URL можно запустить guarded
live smoke вручную:

```bash
ONELAYER_LIVE_WEB_URL=http://127.0.0.1:8091 \
ONELAYER_LIVE_QR_URL='http://127.0.0.1:8091/verify?...' \
npx --prefix tests/e2e-web playwright test \
  --config=playwright.live.config.ts
```

## Backup-панель MVP

Оператор открывает `/admin/backups`, видит стартовые локальные
`BackupCenter`-ы и может создать snapshot, проверить статусы репликации и
запустить bounded recovery flow. Эти центры являются локальным MVP-хранилищем;
географическая независимость и production restore drill относятся к Gate E.

## Ограничения

Контур предназначен для synthetic devnet demo. Он не доказывает законность
исходных данных, production security, независимость recovery-центров или
готовность к работе с реальными персональными данными.

## Обновление verifier и индекса (2026-09-19)

После обновления исходников используйте `./deploy/devnet-demo/native restart`.
Миграция `0007_incident_final_status.sql` требует остановить старые writers:
она сохраняет новые состояния инцидентов и сбрасывает старую пересчитываемую
projection, поскольку ее прежний watermark не доказывал полноту. Исходные
chain events и локальные findings не удаляются. `native migrate`/`start`
отказываются мигрировать при работающем управляемом demo-api; при ручном
запуске остановите также все ручные экземпляры index writer.

После миграции verification может быть unavailable, пока полный scan не
сверится с finalized incident accounts. Если RPC удалил нужную историю,
подключите архивный RPC: нельзя вручную увеличивать watermark для обхода
ошибки. Реальная рабочая БД в ходе разработки этой миграции не изменялась.

Native launcher создает `deploy/devnet-demo/.runtime/native/verifier-trust-policy.json`
с правами 0600 из синтетического issuer seed. Файл содержит только публичные
pins/ключи, version 1, revision = принятый watermark + 1 и expiry через 30 дней; private seed в policy
не записывается. Закреплены demo program, registry/config PDA и полный devnet
genesis hash. Существующий файл не перезаписывается и не продлевается автоматически.
После смены synthetic issuer или истечения policy startup завершится ошибкой.
Оператор должен проверить новые pins и управляемо заменить policy с увеличением
revision; при необходимости сохраните прежний публичный issuer для проверки
легальной истории. Компрометированный ключ нужно отозвать, а не просто продлить.

При запуске verifier вручную обязательны:

- `ONELAYER_TRUST_POLICY_FILE` — путь к проверенной deployment policy;
- `ONELAYER_TRUST_POLICY_MIN_REVISION` — минимально допустимая revision (десятичное число без ведущих нулей);
- `ONELAYER_TRUST_STATE_FILE` — durable anti-rollback watermark; пути по умолчанию нет. Требования: путь каталога без symlink; каталог не совпадает с каталогом policy, не вложен в него и не содержит его (сравнение по realpath, в том числе с реальным расположением policy-файла); каталог принадлежит пользователю verifier и не group/world-writable; все предки до `/` принадлежат root или этому пользователю и не доступны на запись другим (world-writable допустим только со sticky bit, как `/tmp`). Файл открывается с `O_NOFOLLOW`. Native launcher хранит его в `${XDG_STATE_HOME:-$HOME/.local/state}/onelayer-devnet-demo/verifier-trust/accepted.json`;
- ровно один режим: `ONELAYER_TRUST_ROOT_KEYS` (signed) или явный `ONELAYER_TRUST_POLICY_UNSIGNED=1` для synthetic demo. После принятия signed policy unsigned отвергается;
- прежние `ONELAYER_RPC_URL`, `ONELAYER_INCIDENT_INDEX_URL`, `ONELAYER_LOOKUP_URL`.

Signed режим (native demo его не использует) требует дополнительно:

- `ONELAYER_TRUST_ROOT_KEYS=keyId:ed25519hex[,…]` — закреплённый anchor root set (1–32 ключа, без повторов keyId и public key);
- `ONELAYER_TRUST_ROOT_THRESHOLD=k` — сколько различных ключей текущего root set должны подписать policy, rotation и floor (1..n, значения по умолчанию нет);
- `ONELAYER_TRUST_DEPLOYMENT=<base58 genesis>/<registryId>/<programHex lowercase>` — каноничный pin без пробелов; с ним сверяются policy, rotations и floor;
- `ONELAYER_TRUST_FLOOR_FILE` — внешний монотонный floor (`onelayer.signed-trust-floor.v1`): `{deploymentId, minimumPolicyRevision, minimumRootEpoch, issuedAt, expiresAt, nonce:null}`, подписанный threshold текущего root set. Signed режима без floor нет. Недоступный, чужой, неподписанный, истёкший, выпущенный «в будущем» (> 5 мин) floor или floor со сроком действия длиннее допустимого → verifier не стартует. Policy ниже `minimumPolicyRevision` и root set ниже `minimumRootEpoch` отвергаются даже после удаления watermark. Floor должен обновляться внешним источником (floor service / HSM counter / ceremony) чаще, чем истекает;
- `ONELAYER_TRUST_FLOOR_MAX_AGE_SECONDS` (необязательно, по умолчанию 86400, максимум 30 дней) — максимальная длительность `expiresAt − issuedAt`;
- `ONELAYER_TRUST_ROOT_ROTATIONS_FILE` (необязательно) — JSON-массив envelopes `onelayer.signed-trust-root-set.v1` от старых к новым. Каждый payload `{format:"onelayer.trust-root-set.v1", deploymentId, epoch, threshold, keys}` подписан threshold предыдущего set, epoch растёт ровно на 1. Любое битое звено → fail-closed (цепочка не обрезается). После ротации policy и floor принимаются только от нового set. Если файл указан, но отсутствует → `TRUST_ROOT_UNAVAILABLE`;
- `ONELAYER_TRUST_ROOT_EPOCH` (необязательно, по умолчанию 1) — epoch закреплённого anchor. После компрометации threshold ключей старого set оператор перезакрепляет anchor на текущем set (`ROOT_KEYS`/`THRESHOLD`/`ROOT_EPOCH=N`) и оставляет в rotations file только записи с epoch > N; записи старых epoch отвергаются, а не пропускаются.

Watermark (`onelayer.trust-state.v2`) хранит revision, digest, `authenticated`,
`rootEpoch` и digest root set. Меньший root epoch → `TRUST_ROOT_ROLLBACK`, другой
set той же epoch (fork) → `TRUST_ROOT_CONFLICT`. Watermark v1 читается и при
следующем изменении переписывается в v2.

Первый запуск без watermark требует `ONELAYER_TRUST_STATE_BOOTSTRAP=<policy digest>`.
Policy digest — sha256 точных байтов policy JSON-документа, одинаковый для обоих
режимов: в unsigned это файл policy (`sha256sum policy.json`), в signed —
декодированный `payloadBase64` envelope, а не сам envelope
(`jq -r .payloadBase64 envelope.json | base64 -d | sha256sum`). Bootstrap создает
watermark только для документа с этим digest и revision не выше
`max(MIN_REVISION, floor.minimumPolicyRevision) + 1000`; при существующем watermark переменная не действует.
Уберите ее после первого запуска. Demo launcher выполняет bootstrap через
provisioning script только в том запуске, который сам создал policy-файл.

Ротация demo policy: переместите истекший `verifier-trust-policy.json` в сторону и
снова выполните `native start`; новая policy получит revision watermark+1.
Если watermark пропал, а policy осталась, `native start` завершится ошибкой
(fail-closed): восстановите watermark из backup либо, как осознанный сброс
anti-rollback, переместите policy в сторону и выполните `native start`.
В unsigned режиме watermark защищает от случайного отката (восстановление из
backup, ошибка оператора), а не от того, кто может записать policy.

Переход unsigned→signed: signed envelope должен либо содержать byte-identical
payload уже принятой unsigned policy (та же revision), либо иметь revision выше
принятой (не больше чем на 1000). Unsigned watermark переносится как floor;
после первого signed принятия unsigned policy отвергаются.

Stale lock: запись watermark защищена `<state>.lock` (O_EXCL). Если процесс упал
во время записи, следующий запуск через 5 s завершится `TRUST_STATE_LOCKED` с
pid владельца и признаком «NOT running». Автоматически lock не удаляется.
Процедура: убедитесь, что ни verifier, ни provisioning script не используют этот
state (`native status`, `pgrep -af apps/verifier`), затем удалите `<state>.lock`
и повторите запуск.

Структура файла: `apps/verifier/src/trust-policy.ts`. Policy читается при старте;
для применения замены нужен restart. Отсутствующая/невалидная/истекшая policy
не разрешает проверку. Floor проверяется только при старте (без hot reload).
Env revision floor не заменяет защищённое монотонное хранилище: в signed режиме
его роль выполняет внешний подписанный floor; custody trust-root ключей и
производственный источник floor — отдельная задача (ticket 16). Генератор
`apps/verifier/scripts/create-demo-trust-policy.ts` предназначен только для
synthetic demo. Loopback-порты не заменяют production identity/device boundary.

## Долговечные admin sessions (2026-09-20)

API и native launcher теперь используют PostgreSQL для admin accounts, grants,
блокировок и sessions. Для обновления нужен обычный `native restart`, который
сначала останавливает API и применяет additive migration `0008_admin_identity.sql`.
Рабочая база в ходе разработки не изменялась. При первом переходе прежние
in-memory cookies недействительны; после повторного входа новые сессии переживают
restart до истечения 30 минут.

Credentials file задает password authentication и начальные grants только для
еще не существующего аккаунта. Restart не сбрасывает блокировку и не возвращает
права из этого файла. Существующие права меняются доверенной локальной командой
`npm --prefix apps/demo-api run admin:access -- ...` с `ONELAYER_DATABASE_URL_FILE`.
[Синтаксис, семантика отзыва и ограничения](../../docs/admin-access-contract.md).

Потеря identity DB дает отказ, без автоматического перехода на память.
`ONELAYER_SESSION_BACKEND=memory` допустим только в явно выбранных synthetic tests;
launcher фиксирует `postgres`. Откат на старый бинарник с memory sessions не
сохраняет durable revoke policy и не является безопасным способом восстановления.
Таблицы identity нельзя удалять для «сброса входа»: это удалит блокировки и журнал.
OIDC, managed-device admission и независимый audit остаются отдельными задачами.

## Private runtime on NTFS/shared checkouts

PostgreSQL requires a private data directory. If the checkout filesystem reports
all directories as mode 777 (for example this DATA/NTFS mount), keep runtime
state on a Unix filesystem instead:

```bash
export ONELAYER_NATIVE_STATE_DIR="$HOME/.local/state/onelayer-devnet-demo/native"
/usr/bin/python3 apps/desktop/readiness.py --scope stack
./deploy/devnet-demo/native start
```

Use that same environment setting for `status`, `logs`, `stop` and `restart`.
The override must be absolute. New runtime files use `umask 077`. This selects a
separate local database; it does not copy, delete or repair the previous
`deploy/devnet-demo/.runtime/native/postgres` cluster. Preserve the old cluster
and explicitly migrate it if its synthetic records are needed. Applied migration
checksums are still enforced; the override never bypasses that check.

If a stack is already running under the previous state path, stop it using its
previous environment before switching. `stop` under a new path only knows that
path's PID files. Startup and migration refuse shared, unowned or symlinked
runtime roots/PGDATA; they never chmod or delete an old cluster to force a pass.
