# ADR-0010. Отдельный synthetic registry для живого демо

Дата: 2026-10-06. Статус: accepted для локального synthetic/devnet-контура.

Governance-ключ существующего `gov.registry.land` утрачен. Живое демо получает явно выбранный отдельный registry namespace на той же развёрнутой программе: `initialize_registry` создаёт новый PDA из registry hash и назначает подписавшего payer его governance authority. Это сохраняет старые anchors и полномочия и позволяет проверять настоящие devnet-транзакции без новой программы или ослабления авторизации.

Профиль задаёт registry ID, отдельную synthetic DB, key references и отдельную deployment identity verifier trust policy. Launcher показывает выбранный namespace и synthetic/devnet-статус. Default legacy-профиль сохраняется; подмена его config PDA или governance authority не является допустимым fallback. Если выбранный namespace уже занят другой authority, setup отказывает.

Startup поднимает локальные сервисы и выполняет read-only assessment. Setup сначала показывает точные инструкции, payer, аккаунты, rent/fees и результат simulation, затем получает явное подтверждение пользователя перед подписью и отправкой. Повторный setup сверяет owner, discriminator, registry hash и authority и выполняет только недостающие разрешённые шаги. Production provisioning и production acceptance остаются отдельными задачами.

Основание: `InitializeRegistry` в `onchain/programs/onelayer-registry/src/lib.rs:677` использует `init` и seeds `[b"registry", registry_id_hash]`; `GrantOperator` проверяет `has_one = governance_authority`. Допустимость конкретной операции на развёрнутой программе подтверждается simulation, а не одним совпадением исходного кода.
