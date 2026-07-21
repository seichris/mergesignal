alter table app.pull_requests
  add column author_type text
  check (author_type is null or author_type in ('User', 'Bot', 'Organization', 'Mannequin'));

alter table app.pull_requests
  drop constraint pull_requests_check;

update app.pull_requests
set author_type = 'User'
where author_node_id is not null;

alter table app.pull_requests
  add constraint pull_requests_author_identity_check
  check (
    (author_node_id is null and author_login is null and author_type is null)
    or
    (author_node_id is not null and author_login is not null and author_type is not null)
  );

create table app.contributor_history_snapshots (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  actor_node_id text not null,
  observed_login text not null,
  account_created_at timestamptz not null,
  observed_from timestamptz not null,
  observed_until timestamptz not null,
  account_age_days integer not null check (account_age_days >= 0),
  commits integer not null check (commits >= 0),
  issues integer not null check (issues >= 0),
  pull_requests integer not null check (pull_requests >= 0),
  pull_request_reviews integer not null check (pull_request_reviews >= 0),
  active_weeks integer not null check (active_weeks between 0 and 104),
  external_pull_requests_observed integer not null check (external_pull_requests_observed >= 0),
  external_closed_pull_requests integer not null check (
    external_closed_pull_requests between 0 and external_pull_requests_observed
  ),
  external_merged_pull_requests integer not null check (
    external_merged_pull_requests between 0 and external_closed_pull_requests
  ),
  distinct_public_repositories integer not null check (distinct_public_repositories >= 0),
  restricted_contributions integer not null check (restricted_contributions >= 0),
  truncated boolean not null,
  provider_response_digest text not null check (provider_response_digest ~ '^[0-9a-f]{64}$'),
  cache_window_start timestamptz not null,
  cache_expires_at timestamptz not null,
  collected_at timestamptz not null default clock_timestamp(),
  unique (tenant_id, id),
  unique (tenant_id, actor_node_id, cache_window_start),
  check (observed_from < observed_until),
  check (cache_window_start < cache_expires_at)
);

create table app.pr_reputation_assessments (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references app.tenants(id) on delete restrict,
  pull_request_id uuid not null references app.pull_requests(id) on delete restrict,
  publication_id uuid not null unique references app.github_publications(id) on delete restrict,
  history_snapshot_id uuid,
  generation integer not null check (generation > 0),
  head_sha text not null check (head_sha ~ '^[0-9a-f]{40}$'),
  author_node_id text,
  author_login text,
  author_type text check (author_type is null or author_type in ('User', 'Bot', 'Organization', 'Mannequin')),
  status text not null check (status in ('evaluated', 'not_evaluated', 'unavailable')),
  reason text check (
    reason is null or reason in (
      'author_missing',
      'actor_not_user',
      'provider_unavailable',
      'identity_mismatch',
      'invalid_provider_data'
    )
  ),
  account_maturity_score numeric(8, 4) check (account_maturity_score between 0 and 15),
  public_activity_score numeric(8, 4) check (public_activity_score between 0 and 20),
  regularity_score numeric(8, 4) check (regularity_score between 0 and 20),
  merged_pull_requests_score numeric(8, 4) check (merged_pull_requests_score between 0 and 35),
  repository_breadth_score numeric(8, 4) check (repository_breadth_score between 0 and 10),
  final_score integer check (final_score between 0 and 100),
  band text check (band in ('extensive', 'substantial', 'moderate', 'emerging', 'limited')),
  confidence text check (confidence in ('high', 'medium', 'limited')),
  scoring_version text check (scoring_version is null or scoring_version = 'mvp-v1'),
  calculated_at timestamptz not null default clock_timestamp(),
  unique (pull_request_id, generation),
  foreign key (tenant_id, history_snapshot_id)
    references app.contributor_history_snapshots(tenant_id, id) on delete restrict,
  check (
    (
      status = 'evaluated'
      and history_snapshot_id is not null
      and author_node_id is not null
      and author_login is not null
      and author_type = 'User'
      and reason is null
      and account_maturity_score is not null
      and public_activity_score is not null
      and regularity_score is not null
      and merged_pull_requests_score is not null
      and repository_breadth_score is not null
      and final_score is not null
      and band is not null
      and confidence is not null
      and scoring_version is not null
    )
    or
    (
      status <> 'evaluated'
      and history_snapshot_id is null
      and reason is not null
      and account_maturity_score is null
      and public_activity_score is null
      and regularity_score is null
      and merged_pull_requests_score is null
      and repository_breadth_score is null
      and final_score is null
      and band is null
      and confidence is null
      and scoring_version is null
    )
  )
);

create index contributor_history_snapshots_cache_idx
  on app.contributor_history_snapshots (tenant_id, actor_node_id, cache_expires_at desc);

create trigger contributor_history_snapshots_reject_update
before update on app.contributor_history_snapshots
for each row execute function audit.reject_mutation();

create trigger contributor_history_snapshots_reject_delete
before delete on app.contributor_history_snapshots
for each row execute function audit.reject_mutation();

create trigger pr_reputation_assessments_reject_update
before update on app.pr_reputation_assessments
for each row execute function audit.reject_mutation();

create trigger pr_reputation_assessments_reject_delete
before delete on app.pr_reputation_assessments
for each row execute function audit.reject_mutation();

alter table app.contributor_history_snapshots enable row level security;
alter table app.contributor_history_snapshots force row level security;
alter table app.pr_reputation_assessments enable row level security;
alter table app.pr_reputation_assessments force row level security;

create policy tenant_isolation on app.contributor_history_snapshots
  for all to mergesignal_worker
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());
create policy tenant_support on app.contributor_history_snapshots
  for select to mergesignal_support using (tenant_id = app.current_tenant_id());

create policy tenant_isolation on app.pr_reputation_assessments
  for all to mergesignal_worker
  using (tenant_id = app.current_tenant_id())
  with check (tenant_id = app.current_tenant_id());
create policy tenant_support on app.pr_reputation_assessments
  for select to mergesignal_support using (tenant_id = app.current_tenant_id());

grant select, insert on app.contributor_history_snapshots,
  app.pr_reputation_assessments to mergesignal_worker;
grant select on app.contributor_history_snapshots,
  app.pr_reputation_assessments to mergesignal_support;
