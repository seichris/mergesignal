create schema if not exists control;
revoke all on schema control from public;

create table control.github_installations (
  installation_id bigint primary key check (installation_id > 0),
  tenant_id uuid not null unique references app.tenants(id) on delete restrict,
  account_node_id text not null,
  account_login text not null,
  account_type text not null,
  state text not null default 'active' check (state in ('active', 'suspended', 'deleted')),
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp()
);

create table app.github_installation_profiles (
  installation_id bigint primary key check (installation_id > 0),
  tenant_id uuid not null unique references app.tenants(id) on delete restrict,
  account_node_id text not null,
  account_login text not null,
  account_type text not null,
  repository_selection text check (repository_selection in ('all', 'selected')),
  permissions jsonb not null default '{}'::jsonb check (jsonb_typeof(permissions) = 'object'),
  subscribed_events text[] not null default '{}',
  state text not null default 'active' check (state in ('active', 'suspended', 'deleted')),
  last_delivery_id text,
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp()
);

create table app.repositories (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  installation_id bigint not null references app.github_installation_profiles(installation_id) on delete restrict,
  github_repository_id bigint not null check (github_repository_id > 0),
  repository_node_id text not null,
  full_name text not null check (position('/' in full_name) > 1),
  owner_login text not null,
  name text not null,
  private boolean not null,
  default_branch text,
  state text not null default 'active' check (state in ('active', 'removed')),
  provider_updated_at timestamptz,
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp(),
  unique (tenant_id, github_repository_id),
  unique (tenant_id, repository_node_id),
  unique (tenant_id, full_name)
);

create table app.pull_requests (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  repository_id uuid not null references app.repositories(id) on delete restrict,
  github_pull_request_id bigint not null check (github_pull_request_id > 0),
  pull_request_node_id text not null,
  number integer not null check (number > 0),
  state text not null check (state in ('open', 'closed')),
  draft boolean not null,
  head_sha text not null check (head_sha ~ '^[0-9a-f]{40}$'),
  base_sha text not null check (base_sha ~ '^[0-9a-f]{40}$'),
  author_node_id text,
  author_login text,
  provider_updated_at timestamptz not null,
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp(),
  unique (tenant_id, pull_request_node_id),
  unique (repository_id, number),
  unique (repository_id, github_pull_request_id),
  check ((author_node_id is null) = (author_login is null))
);

create table app.pr_output_cursors (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  pull_request_id uuid not null unique references app.pull_requests(id) on delete restrict,
  installation_id bigint not null,
  repository_node_id text not null,
  pull_request_node_id text not null,
  generation integer not null check (generation > 0),
  head_sha text not null check (head_sha ~ '^[0-9a-f]{40}$'),
  canonical_comment_id bigint check (canonical_comment_id is null or canonical_comment_id > 0),
  current_check_run_id bigint check (current_check_run_id is null or current_check_run_id > 0),
  state text not null default 'queued' check (state in ('queued', 'publishing', 'published', 'stale', 'failed')),
  revision integer not null default 1 check (revision > 0),
  updated_at timestamptz not null default clock_timestamp(),
  unique (tenant_id, repository_node_id, pull_request_node_id)
);

create table app.github_publications (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  output_cursor_id uuid not null references app.pr_output_cursors(id) on delete restrict,
  source_delivery_id text not null,
  generation integer not null check (generation > 0),
  head_sha text not null check (head_sha ~ '^[0-9a-f]{40}$'),
  state text not null default 'queued' check (state in ('queued', 'publishing', 'published', 'superseded', 'stale', 'failed')),
  attempt_count integer not null default 0 check (attempt_count >= 0),
  lease_token uuid,
  lease_expires_at timestamptz,
  comment_id bigint check (comment_id is null or comment_id > 0),
  check_run_id bigint check (check_run_id is null or check_run_id > 0),
  observed_head_sha text check (observed_head_sha is null or observed_head_sha ~ '^[0-9a-f]{40}$'),
  last_error_code text check (last_error_code is null or length(last_error_code) <= 80),
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp(),
  completed_at timestamptz,
  unique (output_cursor_id, generation),
  check ((lease_token is null) = (lease_expires_at is null)),
  check (state <> 'published' or completed_at is not null)
);

create table app.github_publication_transitions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  publication_id uuid not null references app.github_publications(id) on delete restrict,
  revision integer not null check (revision > 0),
  prior_state text,
  state text not null check (state in ('queued', 'publishing', 'published', 'superseded', 'stale', 'failed')),
  source_delivery_id text not null,
  head_sha text not null check (head_sha ~ '^[0-9a-f]{40}$'),
  metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
  occurred_at timestamptz not null default clock_timestamp(),
  unique (publication_id, revision),
  check ((revision = 1 and prior_state is null and state = 'queued') or revision > 1)
);

create table app.github_output_observations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  publication_id uuid not null references app.github_publications(id) on delete restrict,
  phase text not null check (phase in ('pre_write', 'post_comment', 'post_check')),
  expected_head_sha text not null check (expected_head_sha ~ '^[0-9a-f]{40}$'),
  observed_head_sha text not null check (observed_head_sha ~ '^[0-9a-f]{40}$'),
  comment_id bigint,
  check_run_id bigint,
  github_app_id bigint not null check (github_app_id > 0),
  marker_digest text not null check (marker_digest ~ '^[0-9a-f]{64}$'),
  observed_at timestamptz not null default clock_timestamp()
);

create table app.installation_reconciliations (
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  installation_id bigint not null references app.github_installation_profiles(installation_id) on delete restrict,
  state text not null default 'due' check (state in ('due', 'running', 'complete', 'failed')),
  last_complete_at timestamptz,
  next_due_at timestamptz not null default clock_timestamp(),
  repository_count integer check (repository_count is null or repository_count >= 0),
  updated_at timestamptz not null default clock_timestamp(),
  primary key (tenant_id, installation_id)
);

create index github_publications_ready_idx
  on app.github_publications (created_at, id)
  where state in ('queued', 'stale', 'failed');

create trigger github_publication_transitions_reject_update
before update on app.github_publication_transitions
for each row execute function audit.reject_mutation();

create trigger github_publication_transitions_reject_delete
before delete on app.github_publication_transitions
for each row execute function audit.reject_mutation();

alter table app.github_installation_profiles enable row level security;
alter table app.github_installation_profiles force row level security;
alter table app.repositories enable row level security;
alter table app.repositories force row level security;
alter table app.pull_requests enable row level security;
alter table app.pull_requests force row level security;
alter table app.pr_output_cursors enable row level security;
alter table app.pr_output_cursors force row level security;
alter table app.github_publications enable row level security;
alter table app.github_publications force row level security;
alter table app.github_publication_transitions enable row level security;
alter table app.github_publication_transitions force row level security;
alter table app.github_output_observations enable row level security;
alter table app.github_output_observations force row level security;
alter table app.installation_reconciliations enable row level security;
alter table app.installation_reconciliations force row level security;

create policy tenant_isolation on app.github_installation_profiles
  for all to mergesignal_worker
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());
create policy tenant_support on app.github_installation_profiles
  for select to mergesignal_support using (tenant_id = app.current_tenant_id());

create policy tenant_isolation on app.repositories
  for all to mergesignal_worker
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());
create policy tenant_support on app.repositories
  for select to mergesignal_support using (tenant_id = app.current_tenant_id());

create policy tenant_isolation on app.pull_requests
  for all to mergesignal_worker
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());
create policy tenant_support on app.pull_requests
  for select to mergesignal_support using (tenant_id = app.current_tenant_id());

create policy tenant_isolation on app.pr_output_cursors
  for all to mergesignal_worker
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());
create policy tenant_support on app.pr_output_cursors
  for select to mergesignal_support using (tenant_id = app.current_tenant_id());

create policy tenant_isolation on app.github_publications
  for all to mergesignal_worker
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());
create policy tenant_support on app.github_publications
  for select to mergesignal_support using (tenant_id = app.current_tenant_id());

create policy tenant_isolation on app.github_publication_transitions
  for all to mergesignal_worker
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());
create policy tenant_support on app.github_publication_transitions
  for select to mergesignal_support using (tenant_id = app.current_tenant_id());

create policy tenant_isolation on app.github_output_observations
  for all to mergesignal_worker
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());
create policy tenant_support on app.github_output_observations
  for select to mergesignal_support using (tenant_id = app.current_tenant_id());

create policy tenant_isolation on app.installation_reconciliations
  for all to mergesignal_worker
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());
create policy tenant_support on app.installation_reconciliations
  for select to mergesignal_support using (tenant_id = app.current_tenant_id());

revoke all on all tables in schema control from public;
revoke all on all tables in schema app from public;

grant select, insert, update on app.github_installation_profiles, app.repositories,
  app.pull_requests, app.pr_output_cursors, app.github_publications,
  app.installation_reconciliations to mergesignal_worker;
grant select, insert on app.github_publication_transitions,
  app.github_output_observations to mergesignal_worker;

grant select on app.github_installation_profiles, app.repositories,
  app.pull_requests, app.pr_output_cursors, app.github_publications,
  app.github_publication_transitions, app.github_output_observations,
  app.installation_reconciliations to mergesignal_support;

create or replace function app.accept_github_webhook(
  p_delivery_id text,
  p_event text,
  p_action text,
  p_body_digest text,
  p_installation_id bigint,
  p_account_node_id text,
  p_account_login text,
  p_account_type text,
  p_repository_selection text,
  p_permissions jsonb,
  p_subscribed_events text[],
  p_payload jsonb
)
returns table (
  tenant_id uuid,
  accepted boolean,
  delivery_record_id uuid,
  outbox_event_id uuid
)
language plpgsql
security definer
set search_path = pg_catalog
as $$
declare
  v_tenant_id uuid;
  v_delivery_id uuid;
  v_outbox_id uuid;
  v_accepted boolean;
begin
  if p_event = 'installation' and p_action = 'created' then
    insert into app.tenants (slug)
    values ('github-' || p_installation_id::text)
    on conflict (slug) do update set slug = excluded.slug
    returning id into v_tenant_id;

    insert into control.github_installations (
      installation_id, tenant_id, account_node_id, account_login, account_type
    ) values (
      p_installation_id, v_tenant_id, p_account_node_id, p_account_login, p_account_type
    )
    on conflict (installation_id) do update set
      account_node_id = excluded.account_node_id,
      account_login = excluded.account_login,
      account_type = excluded.account_type,
      state = 'active',
      updated_at = pg_catalog.clock_timestamp()
    returning control.github_installations.tenant_id into v_tenant_id;
  else
    select installation.tenant_id into v_tenant_id
    from control.github_installations as installation
    where installation.installation_id = p_installation_id;
    if v_tenant_id is null then
      raise exception 'unknown GitHub installation' using errcode = '23503';
    end if;
  end if;

  perform pg_catalog.set_config('app.tenant_id', v_tenant_id::text, true);

  insert into app.github_installation_profiles (
    installation_id, tenant_id, account_node_id, account_login, account_type,
    repository_selection, permissions, subscribed_events, last_delivery_id
  ) values (
    p_installation_id, v_tenant_id, p_account_node_id, p_account_login, p_account_type,
    p_repository_selection, p_permissions, p_subscribed_events, p_delivery_id
  )
  on conflict (installation_id) do update set
    account_node_id = excluded.account_node_id,
    account_login = excluded.account_login,
    account_type = excluded.account_type,
    repository_selection = excluded.repository_selection,
    permissions = excluded.permissions,
    subscribed_events = excluded.subscribed_events,
    last_delivery_id = excluded.last_delivery_id,
    updated_at = pg_catalog.clock_timestamp();

  with inserted as (
    insert into app.webhook_deliveries (
      tenant_id, source, delivery_id, body_digest, payload
    ) values (
      v_tenant_id, 'github', p_delivery_id, p_body_digest, p_payload
    )
    on conflict (source, delivery_id) do nothing
    returning id
  )
  select id, true into v_delivery_id, v_accepted from inserted;

  if v_delivery_id is null then
    select delivery.id into v_delivery_id
    from app.webhook_deliveries as delivery
    where delivery.source = 'github'
      and delivery.delivery_id = p_delivery_id
      and delivery.tenant_id = v_tenant_id
      and delivery.body_digest = p_body_digest;
    v_accepted := false;
  end if;
  if v_delivery_id is null then
    raise exception 'GitHub delivery changed digest or installation' using errcode = '23505';
  end if;

  insert into app.outbox_events (
    tenant_id, aggregate_type, aggregate_id, event_type, dedupe_key, payload
  ) values (
    v_tenant_id,
    'webhook_delivery',
    v_delivery_id::text,
    'github.delivery.accepted',
    'github:' || p_delivery_id,
    pg_catalog.jsonb_build_object(
      'tenantId', v_tenant_id::text,
      'deliveryId', p_delivery_id,
      'deliveryRecordId', v_delivery_id::text
    )
  )
  on conflict (dedupe_key) do nothing
  returning id into v_outbox_id;

  if v_outbox_id is null then
    select event.id into v_outbox_id
    from app.outbox_events as event
    where event.tenant_id = v_tenant_id and event.dedupe_key = 'github:' || p_delivery_id;
  end if;

  return query select v_tenant_id, v_accepted, v_delivery_id, v_outbox_id;
end
$$;

revoke all on function app.accept_github_webhook(
  text, text, text, text, bigint, text, text, text, text, jsonb, text[], jsonb
) from public;
grant execute on function app.accept_github_webhook(
  text, text, text, text, bigint, text, text, text, text, jsonb, text[], jsonb
) to mergesignal_web;

alter default privileges in schema control revoke all on tables from public;
alter default privileges in schema control revoke all on sequences from public;
