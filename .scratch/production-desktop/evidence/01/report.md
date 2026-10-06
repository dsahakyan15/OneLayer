# 01 — Baseline и границы первого этапа

2026-09-19, baseline `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`, изменения не закоммичены. Execution: in-progress; весь acceptance 01 не закрыт.

Исходные F1–F5/S1–S7, приоритеты и сценарии: [review](../../../../docs/security-review-2026-09-18-ru.md). В этом этапе регрессионно воспроизведены переподпись недоверенным issuer, LAN-прослушивание и неполная bootstrap история инцидентов; добавлены отрицательные tests. Recovery findings не воспроизводились заново destructive drill. Владельцы и зависимые gates перечислены в [очереди](../../index.md). Полный production API contract ещё требует реализации identity/workflow.

Threat actors: внешний отправитель certificate package; недоверенная программа в том же transaction/CPI; пользователь без разрешения на объект; скомпрометированный renderer; локальный malware/администратор; скомпрометированный issuer или RPC. Сертификат, payload logs и UI — не основания доверия. Доверенные зависимости текущего этапа: deployment policy/ее оператор, серверная ОС/часы, RPC, program implementation, PostgreSQL. Полный захват этих зависимостей не покрыт локальными проверками. Сейчас storage/backup зависят от одной БД/host — независимых failure domains нет.

Permission matrix, self-approval и системные роли заданы [пайплайном](../../../../docs/application-pipeline-ru.md), пока это требования, не готовый authorization layer. Production ОС/IdP/device enrollment/signer/storage/workload/RPO/RTO не выбирались автоматически: отвечают владелец инфраструктуры и владелец системы, gates 02/20/22/23. Эти неизвестные не мешают локально исправить verifier/index, но не позволяют закрыть baseline для всего приложения.

Baseline `cargo test --all`: 86 PASS; исходные API: 10 файлов PASS. После изменений реальные проверки и ограничения собраны в [отчете реализации](../../../../docs/implementation-progress-2026-09-19.md). Ранний параллельный verifier baseline не считается чистым снимком, поскольку tests уже менялись.

Контракты этого этапа: certificate binary V1 неизменен; trust config version 1 обязателен и вне package; revision floor — deployment env. Incident wire API сохраняет V1 OPEN/RESOLVED; CONFIRMED отображается как OPEN, отдельное resolutionStatus хранит точное состояние. Source of truth incidents — finalized program state/events; PostgreSQL projection восстанавливаема. Refresh атомарен и сериализован; повтор после rollback безопасен. Ошибка history/account validation не публикует новый watermark. Нового mutation API/idempotency contract этот этап не вводит.
