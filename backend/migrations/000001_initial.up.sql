create extension if not exists pgcrypto;

create or replace function starloader_uuid_v7()
returns uuid
language plpgsql
volatile
set search_path = pg_catalog, public
as $$
declare
    unix_milliseconds bigint;
    value bytea := public.gen_random_bytes(16);
begin
    unix_milliseconds := floor(extract(epoch from clock_timestamp()) * 1000)::bigint;
    value := set_byte(value, 0, ((unix_milliseconds >> 40) & 255)::integer);
    value := set_byte(value, 1, ((unix_milliseconds >> 32) & 255)::integer);
    value := set_byte(value, 2, ((unix_milliseconds >> 24) & 255)::integer);
    value := set_byte(value, 3, ((unix_milliseconds >> 16) & 255)::integer);
    value := set_byte(value, 4, ((unix_milliseconds >> 8) & 255)::integer);
    value := set_byte(value, 5, (unix_milliseconds & 255)::integer);
    value := set_byte(value, 6, (get_byte(value, 6) & 15) | 112);
    value := set_byte(value, 8, (get_byte(value, 8) & 63) | 128);
    return encode(value, 'hex')::uuid;
end;
$$;

create table users (
    id uuid primary key default starloader_uuid_v7()
        constraint users_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    email text not null,
    password_hash text not null,
    status text not null default 'active'
        constraint users_status_check check (status in ('active', 'disabled')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint users_email_normalized_check check (email = lower(btrim(email))),
    constraint users_email_unique unique (email)
);

create table licenses (
    id uuid primary key default starloader_uuid_v7()
        constraint licenses_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    license_hmac text not null,
    user_id uuid not null references users(id) on delete restrict,
    product text not null,
    status text not null default 'active'
        constraint licenses_status_check check (status in ('active', 'revoked', 'expired')),
    max_devices integer not null constraint licenses_max_devices_positive_check check (max_devices > 0),
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint licenses_hmac_format_check check (license_hmac ~ '^[0-9a-f]{64}$'),
    constraint licenses_hmac_unique unique (license_hmac),
    constraint licenses_product_not_empty_check check (btrim(product) <> ''),
    constraint licenses_id_user_unique unique (id, user_id)
);

create index licenses_user_id_idx on licenses (user_id);
create index licenses_user_product_status_idx on licenses (user_id, product, status);
create index licenses_status_expires_at_idx on licenses (status, expires_at);

create table devices (
    id uuid primary key default starloader_uuid_v7()
        constraint devices_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    user_id uuid not null references users(id) on delete restrict,
    license_id uuid not null,
    tpm_public_key bytea not null,
    tpm_public_key_sha256 bytea not null
        constraint devices_tpm_public_key_sha256_length_check check (octet_length(tpm_public_key_sha256) = 32),
    smbios_uuid_hmac text,
    motherboard_serial_hmac text,
    bios_serial_hmac text,
    system_disk_serial_hmac text,
    machine_guid_hmac text,
    fingerprint_hmac text not null,
    status text not null default 'active'
        constraint devices_status_check check (status in ('active', 'revoked')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    last_seen_at timestamptz not null default now(),
    constraint devices_license_user_fkey foreign key (license_id, user_id)
        references licenses(id, user_id) on delete restrict,
    constraint devices_hmac_format_check check (
        (smbios_uuid_hmac is null or smbios_uuid_hmac ~ '^[0-9a-f]{64}$') and
        (motherboard_serial_hmac is null or motherboard_serial_hmac ~ '^[0-9a-f]{64}$') and
        (bios_serial_hmac is null or bios_serial_hmac ~ '^[0-9a-f]{64}$') and
        (system_disk_serial_hmac is null or system_disk_serial_hmac ~ '^[0-9a-f]{64}$') and
        (machine_guid_hmac is null or machine_guid_hmac ~ '^[0-9a-f]{64}$') and
        fingerprint_hmac ~ '^[0-9a-f]{64}$'
    ),
    constraint devices_license_tpm_key_unique unique (license_id, tpm_public_key_sha256)
);

create index devices_user_id_idx on devices (user_id);
create index devices_license_status_idx on devices (license_id, status);

create table auth_sessions (
    id uuid primary key default starloader_uuid_v7()
        constraint auth_sessions_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    user_id uuid not null references users(id) on delete restrict,
    license_id uuid not null,
    status text not null default 'pending'
        constraint auth_sessions_status_check check (status in ('pending', 'verified', 'expired')),
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint auth_sessions_license_user_fkey foreign key (license_id, user_id)
        references licenses(id, user_id) on delete restrict
);

create index auth_sessions_user_id_idx on auth_sessions (user_id);
create index auth_sessions_license_id_idx on auth_sessions (license_id);
create index auth_sessions_status_expires_at_idx on auth_sessions (status, expires_at);

create table device_challenges (
    id uuid primary key default starloader_uuid_v7()
        constraint device_challenges_id_uuid_v7_check check ((get_byte(uuid_send(id), 6) >> 4) = 7),
    session_id uuid not null references auth_sessions(id) on delete cascade,
    challenge_sha256 bytea not null
        constraint device_challenges_sha256_length_check check (octet_length(challenge_sha256) = 32),
    expires_at timestamptz not null,
    consumed_at timestamptz,
    created_at timestamptz not null default now(),
    constraint device_challenges_session_unique unique (session_id),
    constraint device_challenges_sha256_unique unique (challenge_sha256),
    constraint device_challenges_consumed_after_created_check check (consumed_at is null or consumed_at >= created_at)
);

create index device_challenges_unconsumed_expires_at_idx
    on device_challenges (expires_at) where consumed_at is null;
