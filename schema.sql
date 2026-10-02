create table if not exists public.contact_submissions (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  name text not null,
  email text not null,
  service text not null default 'Not sure yet',
  brief text not null,
  status text not null default 'new' check (status in ('new','read','replied','archived')),
  email_message_id text,
  confirmation_message_id text
);

alter table public.contact_submissions enable row level security;

-- No public policies: browser visitors cannot read or modify enquiries.
-- The backend uses the Supabase service-role key server-side only.
create index if not exists contact_submissions_created_at_idx on public.contact_submissions (created_at desc);
create index if not exists contact_submissions_status_idx on public.contact_submissions (status);
