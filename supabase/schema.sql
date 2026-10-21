-- Times Tables schema. Already applied to the Supabase project "tmmercer's Project".
-- Re-running in a fresh project is safe on an empty database.

create table public.children (
  id uuid primary key default gen_random_uuid(),
  parent_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 40),
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

alter table public.children enable row level security;
alter table public.attempts enable row level security;

create policy "parents manage their children" on public.children
  for all to authenticated
  using (parent_id = auth.uid())
  with check (parent_id = auth.uid());

create policy "parents read their children's attempts" on public.attempts
  for select to authenticated
  using (exists (select 1 from public.children c where c.id = attempts.child_id and c.parent_id = auth.uid()));

create policy "parents record attempts for their children" on public.attempts
  for insert to authenticated
  with check (exists (select 1 from public.children c where c.id = attempts.child_id and c.parent_id = auth.uid()));

-- Per-fact summary used to choose practice questions
create view public.fact_stats with (security_invoker = true) as
select
  child_id,
  factor_a,
  factor_b,
  count(*) as total,
  count(*) filter (where not correct) as misses,
  avg(response_ms) filter (where correct) as avg_correct_ms,
  max(created_at) as last_seen
from public.attempts
group by child_id, factor_a, factor_b;
