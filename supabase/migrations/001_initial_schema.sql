
-- EliteAuth database setup
-- Run this entire file once in Supabase: SQL Editor -> New query -> Run

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default 'Developer',
  created_at timestamptz not null default now()
);

create table if not exists public.applications (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 80),
  license_prefix text not null default 'ELITE' check (char_length(license_prefix) <= 20),
  key_groups integer not null default 4 check (key_groups between 1 and 10),
  chars_per_group integer not null default 4 check (chars_per_group between 2 and 16),
  key_separator text not null default '-' check (key_separator in ('-', '_', '.', '')),
  key_charset text not null default 'alphanumeric' check (key_charset in ('alphanumeric', 'letters', 'numbers')),
  key_case text not null default 'upper' check (key_case in ('upper', 'lower')),
  exclude_ambiguous boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.licenses (
  id uuid primary key default gen_random_uuid(),
  application_id uuid not null references public.applications(id) on delete cascade,
  key text not null unique,
  status text not null default 'active' check (status in ('active','disabled','banned')),
  hwid text,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);



-- Add customizable license format settings to existing applications tables.
alter table public.applications add column if not exists license_prefix text not null default 'ELITE';
alter table public.applications add column if not exists key_groups integer not null default 4;
alter table public.applications add column if not exists chars_per_group integer not null default 4;
alter table public.applications add column if not exists key_separator text not null default '-';
alter table public.applications add column if not exists key_charset text not null default 'alphanumeric';
alter table public.applications add column if not exists key_case text not null default 'upper';
alter table public.applications add column if not exists exclude_ambiguous boolean not null default true;

create index if not exists applications_owner_id_idx on public.applications(owner_id);
create index if not exists licenses_application_id_idx on public.licenses(application_id);

alter table public.profiles enable row level security;
alter table public.applications enable row level security;
alter table public.licenses enable row level security;

drop policy if exists "Users can read own profile" on public.profiles;
create policy "Users can read own profile"
on public.profiles for select
to authenticated
using (id = auth.uid());

drop policy if exists "Users can update own profile" on public.profiles;
create policy "Users can update own profile"
on public.profiles for update
to authenticated
using (id = auth.uid())
with check (id = auth.uid());

drop policy if exists "Users can read own applications" on public.applications;
create policy "Users can read own applications"
on public.applications for select
to authenticated
using (owner_id = auth.uid());

drop policy if exists "Users can create own applications" on public.applications;
create policy "Users can create own applications"
on public.applications for insert
to authenticated
with check (owner_id = auth.uid());

drop policy if exists "Users can update own applications" on public.applications;
create policy "Users can update own applications"
on public.applications for update
to authenticated
using (owner_id = auth.uid())
with check (owner_id = auth.uid());

drop policy if exists "Users can delete own applications" on public.applications;
create policy "Users can delete own applications"
on public.applications for delete
to authenticated
using (owner_id = auth.uid());

drop policy if exists "Users can read licenses for own applications" on public.licenses;
create policy "Users can read licenses for own applications"
on public.licenses for select
to authenticated
using (
  exists (
    select 1 from public.applications
    where applications.id = licenses.application_id
      and applications.owner_id = auth.uid()
  )
);

drop policy if exists "Users can create licenses for own applications" on public.licenses;
create policy "Users can create licenses for own applications"
on public.licenses for insert
to authenticated
with check (
  exists (
    select 1 from public.applications
    where applications.id = licenses.application_id
      and applications.owner_id = auth.uid()
  )
);

drop policy if exists "Users can update licenses for own applications" on public.licenses;
create policy "Users can update licenses for own applications"
on public.licenses for update
to authenticated
using (
  exists (
    select 1 from public.applications
    where applications.id = licenses.application_id
      and applications.owner_id = auth.uid()
  )
)
with check (
  exists (
    select 1 from public.applications
    where applications.id = licenses.application_id
      and applications.owner_id = auth.uid()
  )
);

drop policy if exists "Users can delete licenses for own applications" on public.licenses;
create policy "Users can delete licenses for own applications"
on public.licenses for delete
to authenticated
using (
  exists (
    select 1 from public.applications
    where applications.id = licenses.application_id
      and applications.owner_id = auth.uid()
  )
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'display_name', 'Developer'))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

grant usage on schema public to authenticated;
grant select, insert, update, delete on public.profiles to authenticated;
grant select, insert, update, delete on public.applications to authenticated;
grant select, insert, update, delete on public.licenses to authenticated;


-- HWID reset request workflow

create table if not exists public.hwid_reset_links (
  id uuid primary key default gen_random_uuid(),
  license_id uuid not null references public.licenses(id) on delete cascade,
  token text not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.hwid_reset_requests (
  id uuid primary key default gen_random_uuid(),
  license_id uuid not null references public.licenses(id) on delete cascade,
  link_id uuid not null references public.hwid_reset_links(id) on delete cascade,
  reason text check (reason is null or char_length(reason) <= 500),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  requested_at timestamptz not null default now(),
  resolved_at timestamptz
);

create index if not exists hwid_reset_links_license_id_idx on public.hwid_reset_links(license_id);
create index if not exists hwid_reset_requests_license_id_idx on public.hwid_reset_requests(license_id);

alter table public.hwid_reset_links enable row level security;
alter table public.hwid_reset_requests enable row level security;

drop policy if exists "Owners manage reset links" on public.hwid_reset_links;
create policy "Owners manage reset links"
on public.hwid_reset_links
for all
to authenticated
using (
  exists (
    select 1 from public.licenses
    join public.applications on applications.id = licenses.application_id
    where licenses.id = hwid_reset_links.license_id
      and applications.owner_id = auth.uid()
  )
)
with check (
  exists (
    select 1 from public.licenses
    join public.applications on applications.id = licenses.application_id
    where licenses.id = hwid_reset_links.license_id
      and applications.owner_id = auth.uid()
  )
);

drop policy if exists "Owners read reset requests" on public.hwid_reset_requests;
create policy "Owners read reset requests"
on public.hwid_reset_requests
for select
to authenticated
using (
  exists (
    select 1 from public.licenses
    join public.applications on applications.id = licenses.application_id
    where licenses.id = hwid_reset_requests.license_id
      and applications.owner_id = auth.uid()
  )
);

grant select, insert, update, delete on public.hwid_reset_links to authenticated;
grant select on public.hwid_reset_requests to authenticated;

create or replace function public.submit_hwid_reset_request(
  token_input text,
  reason_input text default null
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  reset_link public.hwid_reset_links;
begin
  select *
  into reset_link
  from public.hwid_reset_links
  where token = token_input
  for update;

  if reset_link.id is null then
    raise exception 'Invalid HWID reset link';
  end if;

  if reset_link.used_at is not null then
    raise exception 'This HWID reset link has already been used';
  end if;

  if reset_link.expires_at <= now() then
    raise exception 'This HWID reset link has expired';
  end if;

  insert into public.hwid_reset_requests (license_id, link_id, reason)
  values (
    reset_link.license_id,
    reset_link.id,
    nullif(left(coalesce(reason_input, ''), 500), '')
  );

  update public.hwid_reset_links
  set used_at = now()
  where id = reset_link.id;

  return 'Your HWID reset request was submitted for developer approval.';
end;
$$;

create or replace function public.approve_hwid_reset_request(request_id_input uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  reset_request public.hwid_reset_requests;
begin
  select *
  into reset_request
  from public.hwid_reset_requests
  where id = request_id_input
  for update;

  if reset_request.id is null then
    raise exception 'Reset request not found';
  end if;

  if reset_request.status <> 'pending' then
    raise exception 'Reset request is already resolved';
  end if;

  if not exists (
    select 1
    from public.licenses
    join public.applications on applications.id = licenses.application_id
    where licenses.id = reset_request.license_id
      and applications.owner_id = auth.uid()
  ) then
    raise exception 'Not authorized';
  end if;

  update public.licenses
  set hwid = null
  where id = reset_request.license_id;

  update public.hwid_reset_requests
  set status = 'approved', resolved_at = now()
  where id = reset_request.id;
end;
$$;

create or replace function public.reject_hwid_reset_request(request_id_input uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  reset_request public.hwid_reset_requests;
begin
  select *
  into reset_request
  from public.hwid_reset_requests
  where id = request_id_input
  for update;

  if reset_request.id is null then
    raise exception 'Reset request not found';
  end if;

  if reset_request.status <> 'pending' then
    raise exception 'Reset request is already resolved';
  end if;

  if not exists (
    select 1
    from public.licenses
    join public.applications on applications.id = licenses.application_id
    where licenses.id = reset_request.license_id
      and applications.owner_id = auth.uid()
  ) then
    raise exception 'Not authorized';
  end if;

  update public.hwid_reset_requests
  set status = 'rejected', resolved_at = now()
  where id = reset_request.id;
end;
$$;

revoke all on function public.submit_hwid_reset_request(text,text) from public;
grant execute on function public.submit_hwid_reset_request(text,text) to anon, authenticated;

revoke all on function public.approve_hwid_reset_request(uuid) from public;
grant execute on function public.approve_hwid_reset_request(uuid) to authenticated;

revoke all on function public.reject_hwid_reset_request(uuid) from public;
grant execute on function public.reject_hwid_reset_request(uuid) to authenticated;


-- =========================================================
-- DEPLOY-READY LICENSING API ADDITIONS
-- =========================================================

alter table public.applications add column if not exists app_id uuid not null default gen_random_uuid();
alter table public.applications add column if not exists server_secret_hash text;
alter table public.applications add column if not exists version text not null default '1.0.0';
alter table public.applications add column if not exists enabled boolean not null default true;

create unique index if not exists applications_app_id_unique_idx
on public.applications(app_id);

create table if not exists public.license_sessions (
  id uuid primary key default gen_random_uuid(),
  application_id uuid not null references public.applications(id) on delete cascade,
  license_id uuid not null references public.licenses(id) on delete cascade,
  token_hash text not null unique,
  hwid text not null,
  ip_address text,
  user_agent text,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists license_sessions_application_idx
on public.license_sessions(application_id);

create index if not exists license_sessions_license_idx
on public.license_sessions(license_id);

alter table public.license_sessions enable row level security;

drop policy if exists "Owners read own license sessions" on public.license_sessions;
create policy "Owners read own license sessions"
on public.license_sessions for select
to authenticated
using (
  exists (
    select 1
    from public.applications
    where applications.id = license_sessions.application_id
      and applications.owner_id = auth.uid()
  )
);

grant select on public.license_sessions to authenticated;

create or replace function public.create_application_with_credentials(
  name_input text,
  prefix_input text default 'ELITE',
  groups_input integer default 4,
  chars_input integer default 4,
  separator_input text default '-',
  charset_input text default 'alphanumeric',
  case_input text default 'upper',
  exclude_ambiguous_input boolean default true,
  version_input text default '1.0.0'
)
returns table (
  id uuid,
  owner_id uuid,
  app_id uuid,
  server_secret text,
  name text,
  version text
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  generated_secret text;
  created_app public.applications;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  generated_secret :=
    encode(gen_random_bytes(24), 'hex');

  insert into public.applications (
    owner_id,
    name,
    license_prefix,
    key_groups,
    chars_per_group,
    key_separator,
    key_charset,
    key_case,
    exclude_ambiguous,
    version,
    server_secret_hash
  )
  values (
    auth.uid(),
    left(trim(name_input), 80),
    left(trim(coalesce(prefix_input, '')), 20),
    greatest(1, least(10, groups_input)),
    greatest(2, least(16, chars_input)),
    case when separator_input in ('-', '_', '.', '') then separator_input else '-' end,
    case when charset_input in ('alphanumeric', 'letters', 'numbers') then charset_input else 'alphanumeric' end,
    case when case_input in ('upper', 'lower') then case_input else 'upper' end,
    coalesce(exclude_ambiguous_input, true),
    left(coalesce(version_input, '1.0.0'), 30),
    encode(digest(generated_secret, 'sha256'), 'hex')
  )
  returning * into created_app;

  return query
  select
    created_app.id,
    created_app.owner_id,
    created_app.app_id,
    generated_secret,
    created_app.name,
    created_app.version;
end;
$$;

revoke all on function public.create_application_with_credentials(
  text,text,integer,integer,text,text,text,boolean,text
) from public;

grant execute on function public.create_application_with_credentials(
  text,text,integer,integer,text,text,text,boolean,text
) to authenticated;


-- =========================================================
-- ANTI-TAMPERING, SIGNED RESPONSES, AND REPLAY PROTECTION
-- =========================================================
-- The same statements are also available in ANTI_TAMPER_MIGRATION.sql
-- for existing deployments.
-- EliteAuth anti-tampering migration
-- Run this once in Supabase SQL Editor before deploying worker/worker.js.

create extension if not exists pgcrypto;

alter table public.applications
  add column if not exists enforce_integrity boolean not null default false,
  add column if not exists integrity_sha256 text;

alter table public.licenses
  add column if not exists activated_at timestamptz,
  add column if not exists duration_seconds bigint;

alter table public.license_sessions
  add column if not exists challenge_hash text,
  add column if not exists integrity_sha256 text,
  add column if not exists sdk_version text,
  add column if not exists last_seen_at timestamptz;

-- Hash format constraints are added safely for existing projects.
do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'applications_integrity_sha256_format'
      and conrelid = 'public.applications'::regclass
  ) then
    alter table public.applications
      add constraint applications_integrity_sha256_format
      check (integrity_sha256 is null or integrity_sha256 ~ '^[a-fA-F0-9]{64}$');
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'license_sessions_integrity_sha256_format'
      and conrelid = 'public.license_sessions'::regclass
  ) then
    alter table public.license_sessions
      add constraint license_sessions_integrity_sha256_format
      check (integrity_sha256 is null or integrity_sha256 ~ '^[a-fA-F0-9]{64}$');
  end if;
end;
$$;

create table if not exists public.api_nonces (
  id bigint generated by default as identity primary key,
  application_id uuid not null references public.applications(id) on delete cascade,
  nonce text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  unique (application_id, nonce)
);

create index if not exists api_nonces_expires_at_idx
  on public.api_nonces(expires_at);

create table if not exists public.security_events (
  id bigint generated by default as identity primary key,
  application_id uuid not null references public.applications(id) on delete cascade,
  license_id uuid references public.licenses(id) on delete set null,
  event_type text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists security_events_application_created_idx
  on public.security_events(application_id, created_at desc);

alter table public.api_nonces enable row level security;
alter table public.security_events enable row level security;

-- Nonces are Worker-only. No browser policies are intentionally created.
revoke all on public.api_nonces from anon, authenticated;

-- Application owners can inspect security detections in the dashboard later.
drop policy if exists "Owners read own security events" on public.security_events;
create policy "Owners read own security events"
on public.security_events for select
to authenticated
using (
  exists (
    select 1
    from public.applications
    where applications.id = security_events.application_id
      and applications.owner_id = auth.uid()
  )
);

grant select on public.security_events to authenticated;

-- Atomically reserve a short-lived request nonce. Duplicate nonces are rejected.
create or replace function public.reserve_api_nonce(
  application_id_input uuid,
  nonce_input text,
  expires_at_input timestamptz
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.api_nonces
  where expires_at <= now();

  begin
    insert into public.api_nonces(application_id, nonce, expires_at)
    values (
      application_id_input,
      left(nonce_input, 128),
      greatest(expires_at_input, now() + interval '1 minute')
    );
    return true;
  exception when unique_violation then
    return false;
  end;
end;
$$;

revoke all on function public.reserve_api_nonce(uuid, text, timestamptz) from public;
grant execute on function public.reserve_api_nonce(uuid, text, timestamptz) to service_role;

-- Replace the application-creation RPC so dashboard users can configure
-- an approved SHA-256 build hash at creation time.
drop function if exists public.create_application_with_credentials(
  text,text,integer,integer,text,text,text,boolean,text
);

drop function if exists public.create_application_with_credentials(
  text,text,integer,integer,text,text,text,boolean,text,boolean,text
);

create function public.create_application_with_credentials(
  name_input text,
  prefix_input text default 'ELITE',
  groups_input integer default 4,
  chars_input integer default 4,
  separator_input text default '-',
  charset_input text default 'alphanumeric',
  case_input text default 'upper',
  exclude_ambiguous_input boolean default true,
  version_input text default '1.0.0',
  enforce_integrity_input boolean default false,
  integrity_sha256_input text default null
)
returns table (
  id uuid,
  owner_id uuid,
  app_id uuid,
  server_secret text,
  name text,
  version text,
  enforce_integrity boolean,
  integrity_sha256 text
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  generated_secret text;
  normalized_hash text;
  created_app public.applications;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  normalized_hash := lower(nullif(trim(coalesce(integrity_sha256_input, '')), ''));

  if coalesce(enforce_integrity_input, false)
     and (normalized_hash is null or normalized_hash !~ '^[a-f0-9]{64}$') then
    raise exception 'A valid 64-character SHA-256 hash is required when integrity enforcement is enabled';
  end if;

  if normalized_hash is not null and normalized_hash !~ '^[a-f0-9]{64}$' then
    raise exception 'Integrity hash must be a 64-character SHA-256 value';
  end if;

  generated_secret := encode(gen_random_bytes(24), 'hex');

  insert into public.applications (
    owner_id,
    name,
    license_prefix,
    key_groups,
    chars_per_group,
    key_separator,
    key_charset,
    key_case,
    exclude_ambiguous,
    version,
    server_secret_hash,
    enforce_integrity,
    integrity_sha256
  )
  values (
    auth.uid(),
    left(trim(name_input), 80),
    left(trim(coalesce(prefix_input, '')), 20),
    greatest(1, least(10, groups_input)),
    greatest(2, least(16, chars_input)),
    case when separator_input in ('-', '_', '.', '') then separator_input else '-' end,
    case when charset_input in ('alphanumeric', 'letters', 'numbers') then charset_input else 'alphanumeric' end,
    case when case_input in ('upper', 'lower') then case_input else 'upper' end,
    coalesce(exclude_ambiguous_input, true),
    left(coalesce(version_input, '1.0.0'), 30),
    encode(digest(generated_secret, 'sha256'), 'hex'),
    coalesce(enforce_integrity_input, false),
    normalized_hash
  )
  returning * into created_app;

  return query
  select
    created_app.id,
    created_app.owner_id,
    created_app.app_id,
    generated_secret,
    created_app.name,
    created_app.version,
    created_app.enforce_integrity,
    created_app.integrity_sha256;
end;
$$;

revoke all on function public.create_application_with_credentials(
  text,text,integer,integer,text,text,text,boolean,text,boolean,text
) from public;

grant execute on function public.create_application_with_credentials(
  text,text,integer,integer,text,text,text,boolean,text,boolean,text
) to authenticated;
