# ADR-0004. Полный JSON остаётся в Certificate Package

**Дата:** 2026-08-04
**Статус:** принято

## Контекст

Пользователь должен получить полный JSON объекта по QR, но замороженный on-chain протокол публикует batch `merkleRoot` и `manifestHash`, а не произвольный payload записи. Запись полного JSON в Solana потребовала бы нового account layout, изменила бы privacy/storage boundary и создала бы отдельную версию протокола.

## Решение

MVP хранит полный JSON и раскрытие в подписанном `CertificatePackageV1`. QR указывает на package через `certificateId` и `certificateHash`; `/verify` возвращает данные только после проверки QR binding, issuer signature, field/batch Merkle proofs, finalized anchor и incident status. QR может быть выдан, обслужен или проверен только пока on-chain `RegistryConfig.paused = false`; состояние реестра проверяют Admin API, внутренние QR routes и независимый verifier. Все эти routes принадлежат закрытому сайту реестра и доступны только с управляемых рабочих компьютеров сотрудников через private network/VPN; public internet ingress запрещён. Solana остаётся источником доказательства через `merkleRoot` и `manifestHash`.

## Последствия

Цепочка остаётся компактной, selective disclosure сохраняется, а подмена package обнаруживается без доверия к содержимому сайта. Pause реестра немедленно закрывает QR-путь и не позволяет обойти policy прямой передачей package в verifier. Доступность package становится зависимостью внутреннего verifier: если package недоступен, root доказывает anchor, но полный JSON вернуть нельзя. Банк, нотариус, покупатель и другое внешнее лицо не получают прямой доступ к package или verifier; проверку выполняет сотрудник реестра внутри защищённого контура.

Вариант «записать полный JSON в blockchain» отклонён для MVP; он требует отдельной версии account/package protocol и не даёт достаточного выигрыша для текущего synthetic devnet scope.
