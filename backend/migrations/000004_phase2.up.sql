-- Phase 2: RBAC roles, TOTP MFA, security events, organization tenancy.

create table roles (
    id uuid primary key default starloader_uuid_v7()
        constraint roles_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    name text not null,
    description text not null default '',
    permissions text[] not null default '{}',
    built_in boolean not null default false,
    created_at timestamptz not null default now(),
    constraint roles_name_normalized_check check (name = lower(btrim(name))),
    constraint roles_name_unique unique (name)
);

insert into roles (name, description, permissions, built_in) values
    ('owner', 'Full administrative access',
     '{overview.read,users.read,users.write,licenses.read,licenses.write,devices.read,devices.write,sessions.read,sessions.write,audit.read,security.read,admins.read,admins.write}',
     true),
    ('viewer', 'Read-only access to console data',
     '{overview.read,users.read,licenses.read,devices.read,sessions.read,audit.read,security.read}',
     true);

alter table admin_accounts add column role_id uuid references roles(id) on delete restrict;
update admin_accounts set role_id = (select id from roles where name = 'owner');
alter table admin_accounts alter column role_id set not null;
alter table admin_accounts add column totp_secret text;
alter table admin_accounts add column mfa_enrolled boolean not null default false;

create table admin_recovery_codes (
    id uuid primary key default starloader_uuid_v7()
        constraint admin_recovery_codes_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    admin_account_id uuid not null references admin_accounts(id) on delete cascade,
    code_sha256 bytea not null
        constraint admin_recovery_codes_code_sha256_length_check check (octet_length(code_sha256) = 32),
    used_at timestamptz,
    created_at timestamptz not null default now(),
    constraint admin_recovery_codes_code_sha256_unique unique (code_sha256)
);

create index admin_recovery_codes_account_id_idx on admin_recovery_codes (admin_account_id);

-- Short-lived single-use challenges issued between password verification and
-- TOTP confirmation. Only the SHA-256 digest of the challenge token exists.
create table admin_mfa_challenges (
    id uuid primary key default starloader_uuid_v7()
        constraint admin_mfa_challenges_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    admin_account_id uuid not null references admin_accounts(id) on delete cascade,
    token_sha256 bytea not null
        constraint admin_mfa_challenges_token_sha256_length_check check (octet_length(token_sha256) = 32),
    ip_address text not null default '',
    user_agent text not null default '',
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    constraint admin_mfa_challenges_token_sha256_unique unique (token_sha256)
);

create index admin_mfa_challenges_expires_at_idx on admin_mfa_challenges (expires_at);

create table security_events (
    id uuid primary key default starloader_uuid_v7()
        constraint security_events_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    kind text not null,
    severity text not null default 'info'
        constraint security_events_severity_check check (severity in ('info', 'warning', 'critical')),
    admin_account_id uuid references admin_accounts(id) on delete set null,
    actor_email text not null default '',
    ip_sha256 text not null default '',
    user_agent text not null default '',
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    constraint security_events_kind_not_empty_check check (btrim(kind) <> ''),
    constraint security_events_ip_sha256_format_check check (ip_sha256 = '' or ip_sha256 ~ '^[0-9a-f]{64}$')
);

create index security_events_created_at_idx on security_events (created_at desc, id desc);
create index security_events_kind_created_at_idx on security_events (kind, created_at desc);

-- Organization tenancy. Legacy rows are backfilled into the default
-- application; application_id stays nullable so existing client flows are
-- unaffected until per-application scoping is rolled out.
create table organizations (
    id uuid primary key default starloader_uuid_v7()
        constraint organizations_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    name text not null,
    created_at timestamptz not null default now(),
    constraint organizations_name_normalized_check check (name = lower(btrim(name))),
    constraint organizations_name_unique unique (name)
);

create table applications (
    id uuid primary key default starloader_uuid_v7()
        constraint applications_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    organization_id uuid not null references organizations(id) on delete restrict,
    name text not null,
    slug text not null,
    created_at timestamptz not null default now(),
    constraint applications_slug_normalized_check check (slug = lower(btrim(slug))),
    constraint applications_slug_unique unique (slug)
);

create table organization_members (
    id uuid primary key default starloader_uuid_v7()
        constraint organization_members_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    organization_id uuid not null references organizations(id) on delete cascade,
    user_id uuid not null references users(id) on delete cascade,
    created_at timestamptz not null default now(),
    constraint organization_members_organization_user_unique unique (organization_id, user_id)
);

insert into organizations (name) values ('default');
insert into applications (organization_id, name, slug)
values ((select id from organizations where name = 'default'), 'StarLoader', 'starloader');

alter table users add column application_id uuid references applications(id) on delete set null;
alter table licenses add column application_id uuid references applications(id) on delete set null;
alter table devices add column application_id uuid references applications(id) on delete set null;
alter table auth_sessions add column application_id uuid references applications(id) on delete set null;

update users set application_id = (select id from applications where slug = 'starloader') where application_id is null;
update licenses set application_id = (select id from applications where slug = 'starloader') where application_id is null;
update devices set application_id = (select id from applications where slug = 'starloader') where application_id is null;
update auth_sessions set application_id = (select id from applications where slug = 'starloader') where application_id is null;
