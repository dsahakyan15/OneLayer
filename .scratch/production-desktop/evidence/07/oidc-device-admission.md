# 07 — OIDC и admission устройств, synthetic local slice

Дата: 2026-09-20. Baseline: `3b93cd9b72b0962ff5c87df63ce4bba7092c2bc2` плюс существующее dirty tree. Deployment, commit и migration рабочей БД не выполнялись.

## Поведение и invariant

Pinned issuer adapter обменивает одноразовый authorization code с PKCE S256. Случайные state/nonce и HttpOnly browser binding связывают callback с браузером; state потребляется до await. Проверяются подпись RS256/ES256, issuer, audience/azp, exp/iat, nonce, subject и device claim. Endpoint redirects и token-provided key URLs запрещены, HTTP допускается только отдельным localhost test flag. JWT ограничен 16 KiB, HTTP JSON — 64 KiB, timeout — 5s.

PostgresSessionStore допускает только заранее provisioned issuer/subject и enabled device, принадлежащий account. Grants и role берутся из PostgreSQL, claims их не назначают. Session TTL ограничен exp ID token и 30 минутами. Digest bearer, account revision и device revision сохраняются в DB. Account/device revoke, role/resource policy change инвалидируют cookies для следующего authorization read любого API процесса. Login/revoke сериализуются DB locks; audit failure откатывает admission/provisioning mutation. OIDC и demo password modes изолированы.

Trusted maintenance interface: `provisionOidcAccount`, `enrollDevice`, `revokeDevice`, `updateResourcePolicy`, `loginOidc`. Эти методы не являются HTTP self-service role assignment. Migration 0009 additive; SQL CHECK явно отвергает NULL OIDC bindings/device revision, которые иначе проходили бы трехзначную SQL логику.

Coordinator интегрировал `/v2/admin/oidc/start` и callback в реальный main.ts, отключил password login при OIDC и закрыл legacy non-admin certificate/QR/anchor reads через session + unrestricted read/export grants. Narrow scopes получают 403 до lookup. Scope-aware data projection остается отдельной работой.

## Проверки

Среда: Linux, Node v24.10.0, disposable PostgreSQL clusters из local pg_config, настоящий loopback HTTP synthetic IdP, synthetic users/keys/records. Реальные credentials/PII не читались.

- `npm --prefix apps/demo-api test`: 95 PASS, 0 skip в выполненном run (последующие coordinator tests могут увеличить число).
- `npm --prefix apps/demo-api run test:integration`: 27 PASS, 0 skip до добавления HTTP сценария ниже.
- `node --test --experimental-transform-types apps/demo-api/integration/oidc-http.test.ts`: 1 PASS, 0 skip. Запускает реальный main subprocess: origin restriction, password-disabled, OIDC callback cookie, session после restart, denied unauthenticated/narrow `/v1/certificates/fake`, `/v1/qr/fake`, `/qr/fake`, `/c/fake`, `/v1/anchors/1`, немедленный device revoke.
- `npm --prefix apps/demo-api run typecheck`: PASS.
- `git diff --check`: PASS.

Negative tests: wrong issuer/audience/azp, expired/future token, nonce, empty subject/device, forged signature, redirect token/JWKS, oversized JSON, jku, code/state/browser substitution/replay, unknown user/device, cross-mode cookie, role change, disabled account/device, audit rollback, concurrent login/revoke, NULL DB bindings. Два независимых pools проверяют durable admission/revocation. Первоначальный integration run имел cleanup failure (второй pool закрывался после PostgreSQL); порядок cleanup исправлен и suite повторно полностью PASS.

## Review, ограничения, handoff

Авторский review: проверены issuer pinning, mode isolation, transaction boundaries и SQL NULL constraints. Identity agent дополнительно прочитал coordinator OIDC routes/main auth boundaries; fail-closed legacy resources подтверждены actual HTTP. Это не независимое завершение полного ticket review.

Не проверены production corporate IdP, device attestation/MDM (доверяем подписанному device claim pinned IdP), MFA policy, native system-browser callback, load/SLA, recovery anti-rollback. Pending code flows хранятся в памяти процесса и теряются при restart; durable уже выданные sessions сохраняются. Device admission — explicit trusted local provisioning, не самостоятельная enrollment UI. `/internal/register` и `/internal/reconcile` сохраняют synthetic service bearer, scoped service principal gate открыт. Production identity-admin self-elevation separation/workflow остается незавершенным. Ни ticket 07 целиком, ни production readiness этим срезом не закрываются.
