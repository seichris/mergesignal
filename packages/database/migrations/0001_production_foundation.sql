do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'mergesignal_web') then
    create role mergesignal_web nologin nosuperuser nocreatedb nocreaterole noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'mergesignal_worker') then
    create role mergesignal_worker nologin nosuperuser nocreatedb nocreaterole noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'mergesignal_support') then
    create role mergesignal_support nologin nosuperuser nocreatedb nocreaterole noinherit;
  end if;
end
$$;

create schema if not exists app;
create schema if not exists audit;

revoke all on schema app from public;
revoke all on schema audit from public;

grant usage on schema app to mergesignal_web, mergesignal_worker, mergesignal_support;
grant usage on schema audit to mergesignal_web, mergesignal_worker, mergesignal_support;

create or replace function app.current_tenant_id()
returns uuid
language sql
stable
parallel safe
as $$
  select nullif(current_setting('app.tenant_id', true), '')::uuid
$$;

revoke all on function app.current_tenant_id() from public;
grant execute on function app.current_tenant_id() to mergesignal_web, mergesignal_worker, mergesignal_support;

create table app.tenants (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  created_at timestamptz not null default clock_timestamp()
);

create table app.webhook_deliveries (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  source text not null check (source in ('github', 'synthetic')),
  delivery_id text not null check (length(delivery_id) between 1 and 255),
  body_digest text not null check (body_digest ~ '^[0-9a-f]{64}$'),
  payload jsonb not null check (jsonb_typeof(payload) = 'object'),
  received_at timestamptz not null default clock_timestamp(),
  unique (source, delivery_id)
);

create table app.outbox_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  aggregate_type text not null,
  aggregate_id text not null,
  event_type text not null,
  dedupe_key text not null unique,
  payload jsonb not null check (jsonb_typeof(payload) = 'object'),
  state text not null default 'available' check (state in ('available', 'publishing', 'published')),
  attempt_count integer not null default 0 check (attempt_count >= 0),
  available_at timestamptz not null default clock_timestamp(),
  lease_token uuid,
  lease_expires_at timestamptz,
  last_error_code text check (last_error_code is null or length(last_error_code) <= 80),
  created_at timestamptz not null default clock_timestamp(),
  published_at timestamptz,
  check ((lease_token is null) = (lease_expires_at is null)),
  check ((state = 'published') = (published_at is not null)),
  check (state <> 'published' or lease_token is null)
);

create index outbox_events_ready_idx
  on app.outbox_events (available_at, created_at, id)
  where state = 'available';

create table app.workflow_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  workflow_id text not null unique,
  workflow_type text not null,
  task_queue text not null,
  source_delivery_id text not null,
  state text not null default 'started' check (state in ('started', 'completed')),
  started_at timestamptz not null default clock_timestamp(),
  completed_at timestamptz,
  check ((state = 'completed') = (completed_at is not null))
);

create table app.synthetic_activity_attempts (
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  delivery_id text not null,
  attempt_count integer not null default 0 check (attempt_count >= 0),
  updated_at timestamptz not null default clock_timestamp(),
  primary key (tenant_id, delivery_id)
);

create table app.synthetic_results (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  delivery_id text not null,
  workflow_id text not null,
  body_digest text not null check (body_digest ~ '^[0-9a-f]{64}$'),
  activity_attempts integer not null check (activity_attempts > 0),
  completed_at timestamptz not null default clock_timestamp(),
  unique (tenant_id, delivery_id),
  unique (workflow_id)
);

create table audit.events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  event_type text not null,
  actor_type text not null,
  actor_id text not null,
  subject_type text not null,
  subject_id text not null,
  payload jsonb not null default '{}'::jsonb check (jsonb_typeof(payload) = 'object'),
  occurred_at timestamptz not null default clock_timestamp()
);

create index audit_events_tenant_time_idx
  on audit.events (tenant_id, occurred_at desc, id);

create or replace function audit.reject_mutation()
returns trigger
language plpgsql
as $$
begin
  raise exception 'audit events are append-only' using errcode = '55000';
end
$$;

revoke all on function audit.reject_mutation() from public;

create trigger audit_events_reject_update
before update on audit.events
for each row execute function audit.reject_mutation();

create trigger audit_events_reject_delete
before delete on audit.events
for each row execute function audit.reject_mutation();

alter table app.tenants enable row level security;
alter table app.tenants force row level security;
alter table app.webhook_deliveries enable row level security;
alter table app.webhook_deliveries force row level security;
alter table app.outbox_events enable row level security;
alter table app.outbox_events force row level security;
alter table app.workflow_runs enable row level security;
alter table app.workflow_runs force row level security;
alter table app.synthetic_activity_attempts enable row level security;
alter table app.synthetic_activity_attempts force row level security;
alter table app.synthetic_results enable row level security;
alter table app.synthetic_results force row level security;
alter table audit.events enable row level security;
alter table audit.events force row level security;

create policy tenant_isolation on app.tenants
  for all to mergesignal_web, mergesignal_worker, mergesignal_support
  using (id = app.current_tenant_id())
  with check (id = app.current_tenant_id());

create policy tenant_isolation on app.webhook_deliveries
  for all to mergesignal_web, mergesignal_worker, mergesignal_support
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());

create policy tenant_isolation on app.workflow_runs
  for all to mergesignal_web, mergesignal_worker, mergesignal_support
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());

create policy tenant_isolation on app.synthetic_activity_attempts
  for all to mergesignal_web, mergesignal_worker, mergesignal_support
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());

create policy tenant_isolation on app.synthetic_results
  for all to mergesignal_web, mergesignal_worker, mergesignal_support
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());

create policy tenant_isolation on audit.events
  for select to mergesignal_web, mergesignal_worker, mergesignal_support
  using (tenant_id = app.current_tenant_id());

create policy tenant_insert on audit.events
  for insert to mergesignal_web, mergesignal_worker
  with check (tenant_id = app.current_tenant_id());

create policy tenant_web_outbox_select on app.outbox_events
  for select to mergesignal_web, mergesignal_support
  using (tenant_id = app.current_tenant_id());

create policy tenant_web_outbox_insert on app.outbox_events
  for insert to mergesignal_web
  with check (tenant_id = app.current_tenant_id());

create policy worker_outbox_relay on app.outbox_events
  for all to mergesignal_worker
  using (true)
  with check (true);

revoke all on all tables in schema app from public;
revoke all on all tables in schema audit from public;
revoke all on all sequences in schema app from public;
revoke all on all sequences in schema audit from public;

grant select, insert on app.webhook_deliveries to mergesignal_web;
grant select, insert on app.outbox_events to mergesignal_web;
grant select on app.tenants, app.workflow_runs, app.synthetic_results to mergesignal_web;
grant select, insert on audit.events to mergesignal_web;

grant select on app.tenants, app.webhook_deliveries to mergesignal_worker;
grant select, insert, update on app.outbox_events to mergesignal_worker;
grant select, insert, update on app.workflow_runs to mergesignal_worker;
grant select, insert, update on app.synthetic_activity_attempts to mergesignal_worker;
grant select, insert, update on app.synthetic_results to mergesignal_worker;
grant select, insert on audit.events to mergesignal_worker;

grant select on app.tenants, app.webhook_deliveries, app.outbox_events,
  app.workflow_runs, app.synthetic_activity_attempts, app.synthetic_results to mergesignal_support;
grant select on audit.events to mergesignal_support;

alter default privileges in schema app revoke all on tables from public;
alter default privileges in schema audit revoke all on tables from public;
alter default privileges in schema app revoke all on sequences from public;
alter default privileges in schema audit revoke all on sequences from public;
