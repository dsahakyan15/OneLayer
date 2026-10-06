# Desktop security preflight — ticket 02

Дата: 2026-09-19. Baseline commit: `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`.
Статус: только inspection и критерии эксперимента. Native build, установка, SSO, signer и update tests **не выполнены**. Ticket 02 не закрыт. Пакеты не устанавливались, credentials не читались.

## Решение и границы

Tauri 2 остается кандидатом, без security approval. Предпочтение Tauri в исходном ADR-0007 недостаточно обосновано повторным использованием React; выбор требует следующих одинаковых проверок для обоих кандидатов. Альтернатива для сравнения — Qt Widgets без WebEngine; это desktop toolkit, а не обещание безопасности или требование перейти на C++. Если организация выберет одну ОС, следует также оценить ее штатный native toolkit.

Все лица используют установленную программу; права на действия, объекты и поля проверяет сервер. Внешним лицам результат передает сотрудник. Предполагаем, что обычный UI может быть скомпрометирован. Полный захват ОС не решается выбором UI framework. Защита от чтения разрешенного документа зараженным UI также не гарантируется.

## Фактически проверенное окружение

| Проверка | Наблюдение |
|---|---|
| `uname -srm`, `/etc/os-release` | Linux Mint 22.1, Linux 6.8.0-106-generic, x86_64 |
| `node --version`, `npm --version` | v24.10.0, 11.6.1 |
| `rustc --version`, `cargo --version` | 1.97.1, 1.97.1 |
| `command -v cc cmake qmake6 WebKitWebDriver` | Только `/usr/bin/cc` найден |
| `command -v tauri` | Не найден в PATH; это не проверка npm registry |
| `pkg-config --modversion gtk+-3.0 webkit2gtk-4.1` | Ошибка: development metadata обоих пакетов отсутствует |
| `dpkg-query` runtime packages | GTK 3.24.41-4ubuntu1.3; WebKitGTK 2.50.4-0ubuntu0.24.04.1; libsecret 0.21.4-1build3 |
| Наличие DISPLAY/WAYLAND_DISPLAY | Обе переменные заданы; живое native окно и доступ автоматизации не проверены |
| Поиск файлов Tauri вне node_modules/target | Desktop manifest/config/capabilities не найдены |

Наличие runtime WebKit не означает возможности собрать Tauri: нужны development dependencies, CLI/crates и согласованный lockfile. Версии выше — inventory, а не результат CVE-аудита. Qt development toolkit тоже не обнаружен указанными проверками. Linux lab не доказывает поддержку Windows/macOS. Требования к зависимостям: [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

## Что переносится из текущего UI

- `apps/mvp-web/package.json`: Next 16.2.12, React 19.2.8; отдельной библиотеки NextUI в dependencies нет.
- Компоненты `components/*` — источник повторно используемых представлений. `next/link`, `next/navigation`, server pages и текущую маршрутизацию нужно заменить или адаптировать.
- `lib/api.ts` использует same-origin `/api/*`; `lib/proxy.ts` и `app/api/*/route.ts` требуют Next server. Они не превращаются в static desktop assets. Нужно явно выбрать authenticated native transport и серверный API contract, не запускать произвольный proxy/Node sidecar ради переноса.
- `lib/wallet.ts` ищет browser Wallet Standard providers. Наличие extension в системном браузере не означает ее наличия в WebView. Current signing UI нельзя объявлять переносимым до native signer smoke.
- `next.config.ts` задает HTTP headers, но это не desktop CSP и не native command permissions. [Tauri Next.js guide](https://v2.tauri.app/start/frontend/nextjs/) требует static frontend, а не Next server внутри клиента.

## Сравниваемые кандидаты

| Критерий | Tauri 2 + локальные React assets | Qt Widgets без WebEngine |
|---|---|---|
| Поверхность UI | HTML/JS/WebView + Rust IPC | Widgets + native code и выбранные bindings |
| Повторное использование UI | Возможно для client components после отделения Next/transport | Представления придется реализовать заново; API/protocol fixtures сохраняются |
| Изоляция UI | Capabilities/scopes с проверкой всех custom commands | Выделенный broker/process boundary нужно спроектировать самостоятельно |
| Подмена действия | Capabilities не доказывают согласие пользователя на конкретные bytes | Native dialog в захваченном UI процессе также не доказывает согласие |
| Ключи и доли | Не в renderer; узкий broker/внешний signer | Не в обычном UI; тот же broker/внешний signer |
| Maintenance | App/Rust/npm + OS WebView patch policy | App/native toolkit/bindings + OS patch policy |
| Фактическое evidence здесь | Только inspection | Только предложенный comparator |

Tauri различает frontend/core, но plugins и core обладают системными полномочиями процесса; нельзя выдавать Rust core за автоматически sandboxed. [Tauri security](https://v2.tauri.app/security/). Разрешения окон необходимо тестировать с учетом объединения capabilities. [Capabilities](https://v2.tauri.app/security/capabilities/). Qt Widgets предоставляет классические desktop widgets; из этого не следует наличие безопасного signer или изоляции процессов. [Qt Widgets](https://doc.qt.io/qt-6/qtwidgets-index.html).

## Обязательные native adversarial tests

Это спецификация будущих проверок, **не результаты**. Для каждой сохранить commit/dirty diff, lockfiles, OS/runtime versions, binary digest, команды, sanitized trace и PASS/FAIL/BLOCKED.

| ID | Действие теста | Критерий прохождения |
|---|---|---|
| D01 | Из установленного release приложения вызвать неразрешенные IPC commands, открыть второе окно, навигировать на чужой origin | Нельзя получить shell, произвольный filesystem/network, credential-read; custom commands валидируют payload и scope |
| D02 | Подменить UI test harness: показать документ A, запросить подпись B; изменить root/target/cluster/version/action после review | Signer получает immutable intent из доверенного источника; независимое подтверждение отображает существенные параметры B и не принимает согласие на A; сервер отклоняет mismatch |
| D03 | Повторить уже подписанный intent, сменить пользователя/устройство, дождаться expiry, изменить bytes | Отказ или один ранее зафиксированный effect; нет новой операции по replay |
| D04 | Скомпрометированный renderer вызывает разрешенный signing command без взаимодействия пользователя | Нет тихой критической подписи; проверяемое подтверждение вне данного renderer. Просто hash или generic «Approve» недостаточны |
| D05 | Native login через внешний браузер; чужой state/nonce, неверный PKCE, повтор callback, перезапуск в середине | Ошибки отклонены; callback одноразовый; token не возвращается в renderer. Проверить issuer/audience и привязку сессии |
| D06 | Logout, device/user revoke при открытом окне; попытка прямого API и offline mutation | Сервер отклоняет отозванный доступ; нет продолжения запрещенных действий; UI сообщает состояние |
| D07 | С synthetic canary secrets проверить renderer storage/IPC responses/logs/crash files/export/temp; locked credential store | Нет tokens/private keys/shares в этих каналах; locked store не приводит к plaintext fallback |
| D08 | Подмененный update, неверный ключ, старый подписанный release, обрыв установки | Проверяемый отказ; политика rollback/minimum version; установленная рабочая версия сохраняется или восстанавливается по проверенному recovery пути |
| D09 | Просроченный/чужой TLS certificate; попытка поменять доверенный issuer/program/config из package/renderer | Нет обхода TLS/trust policy, положительный verdict не появляется |
| D10 | Export/clipboard/print под Auditor/Employee с чужим object ID и запрещенным полем | Серверная disclosure policy действует и без UI; локальные temp files и их cleanup проверены |
| D11 | Если добавлен PDF/Office preview: malformed/huge files, embedded links/scripts, parser crash | Изолированный ограниченный parser без signing credentials/IPC; лимиты ресурсов; нет автоматического исполнения/сетевого fetch; отказ preview не меняет проверяемое содержимое |
| D12 | Устаревший OS/WebView/клиент, отсутствующий patch/admission сигнал | Заранее определенная политика допуска и отказа проверена; собственное заявление клиента о версии не принимается за device attestation |

OIDC использует внешний user-agent и PKCE по [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252). Подпись обновления — отдельна от OS installer signing и от политики запрета downgrade; [Tauri updater](https://v2.tauri.app/plugin/updater/) не заменяет весь release gate.

Для D02/D04 внешний браузер на том же host дает отделение от renderer, но не от захваченной ОС. HSM защищает извлечение ключа, однако сам по себе не доказывает смысл согласия человека. Если реальное устройство подписания не показывает необходимые параметры, нужен отдельно проверенный review/approval channel. Recovery shares передаются только в изолированную Recovery Operation, не на общий UI экран трех участников.

## Ближайший небольшой executable spike

1. В отдельном lab проекте зафиксировать Linux candidate dependencies и собрать минимальное установленное окно с локальным UI, без реальных документов/ключей. Tauri и Qt сравнивать на одинаковых трех действиях: чтение synthetic записи, запрос intent, получение результата.
2. Поднять disposable test identity/backend и broker с двумя узкими операциями `read_record` и `request_approval`. Не добавлять общий `execute`, произвольный HTTP proxy или `read_secret`. Для malicious UI использовать отдельную test build конфигурацию; injection harness не попадает в release artifact.
3. Выполнить D01–D05 на реальном окне; browser unit tests не заменяют эти проверки. Минимальный signer работает с test keys и exact bytes, независимый review обязателен для оценки D02/D04.
4. Создать два lab update artifacts; выполнить D08 и reboot/restart. Затем сравнить evidence обоих кандидатов и записать выбор в ADR с открытыми ограничениями.

Зависимости для исполнения: development toolkits и пакеты; выбранная первая ОС (Linux допустим только как lab); доступный native test runner/ручная сессия; test IdP; проверяемый signer/review route; disposable signing credentials для update. Production OS, IdP, hardware custody, device admission и организация patch rollout еще не определены. Эти пробелы не блокируют исправление server/verifier сейчас, но блокируют утверждение production desktop.
