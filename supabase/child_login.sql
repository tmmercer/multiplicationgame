-- Child username/password login. Run this once in the Supabase SQL Editor.
-- Nothing is dropped. The earlier parent-account tables (empty) are renamed with an _old suffix.

create extension if not exists pgcrypto with schema extensions;

-- Move the old, empty tables and their names out of the way
alter view if exists public.fact_stats rename to fact_stats_old;
alter table if exists public.attempts rename to attempts_old;
alter table if exists public.children rename to children_old;
alter index if exists public.attempts_pkey rename to attempts_old_pkey;
alter index if exists public.attempts_child_fact_idx rename to attempts_old_child_fact_idx;
alter index if exists public.children_pkey rename to children_old_pkey;
alter sequence if exists public.attempts_id_seq rename to attempts_old_id_seq;

create table public.children (
  id uuid primary key default gen_random_uuid(),
  username text not null unique check (username ~ '^[a-z0-9_]{3,20}$'),
  display_name text not null check (char_length(display_name) between 1 and 40),
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table public.sessions (
  token uuid primary key default gen_random_uuid(),
  child_id uuid not null references public.children(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table public.attempts (
  id bigserial primary key,
  child_id uuid not null references public.children(id) on delete cascade,
  factor_a smallint not null check (factor_a between 2 and 12),
  factor_b smallint not null check (factor_b between 2 and 12),
  correct boolean not null,
  response_ms integer check (response_ms is null or response_ms >= 0),
  created_at timestamptz not null default now()
);

create index attempts_child_fact_idx on public.attempts (child_id, factor_a, factor_b, created_at desc);

-- Lock the tables: the browser can't touch them directly. Everything goes through the functions below.
alter table public.children enable row level security;
alter table public.sessions enable row level security;
alter table public.attempts enable row level security;
revoke all on public.children, public.sessions, public.attempts from anon, authenticated;

-- Returns the child for a valid session token, or raises an error
create or replace function public.require_child(p_token uuid)
returns uuid language plpgsql stable security definer set search_path = public, extensions as $$
declare cid uuid;
begin
  select s.child_id into cid from public.sessions s where s.token = p_token;
  if cid is null then raise exception 'Please log in again'; end if;
  return cid;
end $$;

create or replace function public.register_child(p_username text, p_password text, p_display_name text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare
  uname text := lower(trim(p_username));
  cid uuid;
  tok uuid;
begin
  if uname !~ '^[a-z0-9_]{3,20}$' then
    raise exception 'Username must be 3-20 letters, numbers, or underscores';
  end if;
  if char_length(coalesce(p_password, '')) < 4 then
    raise exception 'Password must be at least 4 characters';
  end if;
  if exists (select 1 from public.children where username = uname) then
    raise exception 'That username is already taken';
  end if;
  insert into public.children (username, display_name, password_hash)
  values (uname, trim(p_display_name), crypt(p_password, gen_salt('bf')))
  returning id into cid;
  insert into public.sessions (child_id) values (cid) returning token into tok;
  return json_build_object('token', tok, 'name', trim(p_display_name), 'username', uname);
end $$;

create or replace function public.login_child(p_username text, p_password text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare
  rec record;
  tok uuid;
begin
  select id, display_name, username, password_hash into rec
  from public.children where username = lower(trim(p_username));
  if rec.id is null or rec.password_hash <> crypt(p_password, rec.password_hash) then
    raise exception 'Wrong username or password';
  end if;
  insert into public.sessions (child_id) values (rec.id) returning token into tok;
  return json_build_object('token', tok, 'name', rec.display_name, 'username', rec.username);
end $$;

create or replace function public.me_child(p_token uuid)
returns json language plpgsql stable security definer set search_path = public, extensions as $$
declare rec record;
begin
  select c.display_name, c.username into rec
  from public.sessions s join public.children c on c.id = s.child_id
  where s.token = p_token;
  if rec.username is null then return null; end if;
  return json_build_object('name', rec.display_name, 'username', rec.username);
end $$;

create or replace function public.logout_child(p_token uuid)
returns void language sql security definer set search_path = public as $$
  delete from public.sessions where token = p_token;
$$;

create or replace function public.record_attempt(p_token uuid, p_a int, p_b int, p_correct boolean, p_ms int)
returns void language plpgsql security definer set search_path = public as $$
begin
  insert into public.attempts (child_id, factor_a, factor_b, correct, response_ms)
  values (public.require_child(p_token), p_a, p_b, p_correct, p_ms);
end $$;

create or replace function public.get_fact_stats(p_token uuid)
returns table(factor_a smallint, factor_b smallint, total bigint, misses bigint)
language plpgsql stable security definer set search_path = public as $$
begin
  return query
  select a.factor_a, a.factor_b, count(*)::bigint, count(*) filter (where not a.correct)::bigint
  from public.attempts a
  where a.child_id = public.require_child(p_token)
  group by a.factor_a, a.factor_b;
end $$;

-- Only the public API key can call these functions, and only these
revoke all on function public.require_child(uuid) from public, anon, authenticated;
revoke all on function public.register_child(text, text, text) from public;
revoke all on function public.login_child(text, text) from public;
revoke all on function public.me_child(uuid) from public;
revoke all on function public.logout_child(uuid) from public;
revoke all on function public.record_attempt(uuid, int, int, boolean, int) from public;
revoke all on function public.get_fact_stats(uuid) from public;
grant execute on function public.register_child(text, text, text) to anon, authenticated;
grant execute on function public.login_child(text, text) to anon, authenticated;
grant execute on function public.me_child(uuid) to anon, authenticated;
grant execute on function public.logout_child(uuid) to anon, authenticated;
grant execute on function public.record_attempt(uuid, int, int, boolean, int) to anon, authenticated;
grant execute on function public.get_fact_stats(uuid) to anon, authenticated;
