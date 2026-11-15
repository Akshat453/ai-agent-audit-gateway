-- AGW database roles (08 §2). Run once as a superuser against the agw database.
-- psql variables: migrator_password, app_password (never hard-coded; come from .env).
--   agw_migrator: owns every table, runs Alembic, runs operator/admin commands.
--   agw_app:      runtime role, least privilege; never owner, so it cannot disable triggers.

CREATE ROLE agw_migrator LOGIN PASSWORD :'migrator_password';
CREATE ROLE agw_app LOGIN PASSWORD :'app_password';

DO $$
BEGIN
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT, CREATE, TEMPORARY ON DATABASE %I TO agw_migrator', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO agw_app', current_database());
END
$$;

ALTER SCHEMA public OWNER TO agw_migrator;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO agw_app;
