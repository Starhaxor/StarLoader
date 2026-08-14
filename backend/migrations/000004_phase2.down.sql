alter table auth_sessions drop column if exists application_id;
alter table devices drop column if exists application_id;
alter table licenses drop column if exists application_id;
alter table users drop column if exists application_id;

drop table if exists organization_members;
drop table if exists applications;
drop table if exists organizations;

drop table if exists security_events;
drop table if exists admin_mfa_challenges;
drop table if exists admin_recovery_codes;

alter table admin_accounts drop column if exists mfa_enrolled;
alter table admin_accounts drop column if exists totp_secret;
alter table admin_accounts drop column if exists role_id;

drop table if exists roles;
