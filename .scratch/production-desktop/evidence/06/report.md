# 06 — Закрытие LAN-прослушивания demo

2026-09-19, working tree поверх `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2`. Execution: in-progress (production private ingress не реализован).

API и verifier слушают 127.0.0.1; Next start содержит явный `-H 127.0.0.1`. До исправления regression native API провалился на успешном LAN-соединении. После исправления `tests/e2e/native-bind.test.ts` запускает реальные package startup commands для API, verifier и собранного Next и проверяет localhost success/LAN ECONNREFUSED. Все три PASS; весь корневой E2E — 9 PASS без skips на данной машине.

Тест LAN касается подключения к собственному адресу сетевого интерфейса, не удаленного физического устройства. CI без готового Next build явно пропускает web test. IdP/VPN/device admission, production reverse proxy, multi-host topology и RBAC остаются последующим этапом. Loopback не защищает от локального malware. [Общий отчет](../../../../docs/implementation-progress-2026-09-19.md).
