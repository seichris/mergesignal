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
  v_account_node_id text;
  v_account_login text;
  v_account_type text;
  v_repository_selection text;
  v_permissions jsonb;
  v_subscribed_events text[];
begin
  if p_event = 'installation' and p_action = 'created' then
    if p_account_node_id is null or p_account_login is null or p_account_type is null then
      raise exception 'GitHub installation creation is missing account metadata' using errcode = '23502';
    end if;

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

  select
    pg_catalog.coalesce(p_account_node_id, profile.account_node_id),
    pg_catalog.coalesce(p_account_login, profile.account_login),
    pg_catalog.coalesce(p_account_type, profile.account_type),
    pg_catalog.coalesce(p_repository_selection, profile.repository_selection),
    pg_catalog.coalesce(p_permissions, profile.permissions),
    pg_catalog.coalesce(p_subscribed_events, profile.subscribed_events)
  into
    v_account_node_id,
    v_account_login,
    v_account_type,
    v_repository_selection,
    v_permissions,
    v_subscribed_events
  from (values (1)) as singleton(value)
  left join app.github_installation_profiles as profile
    on profile.installation_id = p_installation_id and profile.tenant_id = v_tenant_id;

  if v_account_node_id is null or v_account_login is null or v_account_type is null then
    raise exception 'GitHub installation metadata is unavailable' using errcode = '23503';
  end if;

  insert into app.github_installation_profiles (
    installation_id, tenant_id, account_node_id, account_login, account_type,
    repository_selection, permissions, subscribed_events, last_delivery_id
  ) values (
    p_installation_id, v_tenant_id, v_account_node_id, v_account_login, v_account_type,
    v_repository_selection, pg_catalog.coalesce(v_permissions, '{}'::jsonb),
    pg_catalog.coalesce(v_subscribed_events, '{}'::text[]), p_delivery_id
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
