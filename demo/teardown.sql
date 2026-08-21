-- Removes everything demo/setup.sql created.
-- Run as a superuser:
--   psql -U postgres -h localhost -d postgres -f demo/teardown.sql

DROP DATABASE IF EXISTS sol_demo;
DROP ROLE IF EXISTS app_admin;
DROP ROLE IF EXISTS sol_audit;
