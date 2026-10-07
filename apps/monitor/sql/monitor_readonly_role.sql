-- Ticket 12: отдельная read-only роль независимого Monitor.
--
-- Применяет владелец БД/миграций (НЕ часть db/migrations: роль — deployment
-- boundary Monitor-а, а не схема приложения). Пароль задаётся отдельно
-- оператором (`ALTER ROLE onelayer_monitor PASSWORD ...` или внешний IdP) и
-- хранится только в секрет-хранилище Monitor-а, не у Builder/API.
--
-- Инварианты:
--  * только SELECT на наблюдаемые таблицы workflow/publication;
--  * нет членства в onelayer_runtime и других ролях приложения;
--  * нет SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS;
--  * сессии по умолчанию read-only (дополнительный барьер, не основной);
--  * Monitor при старте проверяет отсутствие write-привилегий и отказывается
--    работать с учётными данными, способными писать.
-- Скрипт идемпотентен.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'onelayer_monitor') THEN
    CREATE ROLE onelayer_monitor LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
  END IF;
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO onelayer_monitor', current_database());
END $$;

ALTER ROLE onelayer_monitor NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 4;
ALTER ROLE onelayer_monitor SET default_transaction_read_only = on;
ALTER ROLE onelayer_monitor SET statement_timeout = '60s';
ALTER ROLE onelayer_monitor SET idle_in_transaction_session_timeout = '60s';

-- Снять любые ранее выданные привилегии и членства.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM onelayer_monitor;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM onelayer_monitor;
REVOKE CREATE ON SCHEMA public FROM onelayer_monitor;
DO $$
DECLARE r text;
BEGIN
  FOR r IN SELECT g.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
           JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = 'onelayer_monitor'
  LOOP
    EXECUTE format('REVOKE %I FROM onelayer_monitor', r);
  END LOOP;
END $$;

GRANT USAGE ON SCHEMA public TO onelayer_monitor;
GRANT SELECT ON
  wf_record,
  wf_version,
  wf_outbox,
  wf_source_cursor,
  wf_source_event,
  wf_publication,
  wf_publication_item,
  wf_publication_intent,
  wf_publication_anchor
TO onelayer_monitor;
