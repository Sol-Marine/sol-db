-- Creates a local demo database with DELIBERATELY INSECURE configuration
-- so you can watch sol-db detect real findings end-to-end.
--
-- Run as a superuser (adjust -U as needed):
--   psql -U postgres -h localhost -d postgres -f demo/setup.sql
--
-- Everything created here is throwaway. Remove it later with teardown.sql.

-- 1. Demo database -----------------------------------------------------------
SELECT 'CREATE DATABASE sol_demo'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sol_demo')\gexec

\connect sol_demo

-- 2. Tables, including sensitive-named ones WITHOUT row level security -------
CREATE TABLE IF NOT EXISTS public.users (
  id serial PRIMARY KEY,
  email text,
  password_hash character varying(255),
  api_key text
);

CREATE TABLE IF NOT EXISTS public.payment_cards (
  id serial PRIMARY KEY,
  user_id integer REFERENCES public.users(id),
  pan character varying(32)
);

CREATE TABLE IF NOT EXISTS public.countries (
  code text PRIMARY KEY,
  name text
);

INSERT INTO public.countries (code, name)
VALUES ('US', 'United States'), ('ET', 'Ethiopia')
ON CONFLICT DO NOTHING;

-- 3. Over-permissive PUBLIC grants --------------------------------------------
GRANT SELECT ON public.users TO PUBLIC;              -- medium: PUBLIC can read users
GRANT INSERT, DELETE ON public.countries TO PUBLIC;  -- critical: PUBLIC can write
GRANT CREATE ON SCHEMA public TO PUBLIC;             -- high: anyone can create objects

-- 4. A superuser login role (cluster-wide; dropped by teardown.sql) -----------
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_admin') THEN
    CREATE ROLE app_admin LOGIN SUPERUSER PASSWORD 'demo-only-change-me';
  END IF;
END $$;

-- 5. The dedicated least-privilege audit role sol-db will connect as ----------
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sol_audit') THEN
    CREATE ROLE sol_audit LOGIN PASSWORD 'audit-demo-1234';
  END IF;
END $$;

GRANT CONNECT ON DATABASE sol_demo TO sol_audit;
GRANT USAGE ON SCHEMA public TO sol_audit;
-- That's all. No table privileges: sol-db reads catalogs only.

\echo 'Demo ready. Now set AUDIT_DB_URL=postgres://sol_audit:audit-demo-1234@localhost:5432/sol_demo?sslmode=disable'
