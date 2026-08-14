create table admin_accounts (
    id uuid primary key default starloader_uuid_v7()
        constraint admin_accounts_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    email text not null,
    password_hash text not null,
    status text not null default 'active'
        constraint admin_accounts_status_check check (status in ('active', 'disabled', 'locked')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint admin_accounts_email_normalized_check check (email = lower(btrim(email))),
    constraint admin_accounts_email_unique unique (email)
);

create table admin_sessions (
    id uuid primary key default starloader_uuid_v7()
        constraint admin_sessions_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    admin_account_id uuid not null references admin_accounts(id) on delete restrict,
    token_sha256 bytea not null
        constraint admin_sessions_token_sha256_length_check check (octet_length(token_sha256) = 32),
    ip_address text not null default '',
    user_agent text not null default '',
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    revoked_at timestamptz,
    constraint admin_sessions_token_sha256_unique unique (token_sha256),
    constraint admin_sessions_revoked_after_created_check check (revoked_at is null or revoked_at >= created_at)
);

create index admin_sessions_account_id_idx on admin_sessions (admin_account_id);
create index admin_sessions_active_expires_at_idx on admin_sessions (expires_at) where revoked_at is null;

create table audit_logs (
    id uuid primary key default starloader_uuid_v7()
        constraint audit_logs_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    admin_account_id uuid references admin_accounts(id) on delete set null,
    actor_email text not null default '',
    action text not null,
    resource_type text not null default '',
    resource_id text not null default '',
    ip_sha256 text not null default '',
    user_agent text not null default '',
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    constraint audit_logs_action_not_empty_check check (btrim(action) <> ''),
    constraint audit_logs_ip_sha256_format_check check (ip_sha256 = '' or ip_sha256 ~ '^[0-9a-f]{64}$'),
    constraint audit_logs_admin_account_actor_check check (admin_account_id is not null or btrim(actor_email) <> '')
);

create index audit_logs_created_at_idx on audit_logs (created_at desc, id desc);
