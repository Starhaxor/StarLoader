# StarLoader Proof-Bound Client Design

## Goal

StarLoader authenticates with email/password and a fresh TPM challenge on every process launch and after every access-token expiry. It never persists or refreshes an authenticated session. Every protected request is bound to the access token, request method, canonical HTTPS URI, and the non-exportable TPM P-256 key.

## Client security contract

- The access token lives in process memory only and expires exactly 600 seconds after `iat`.
- StarLoader has no refresh-token, offline-lease, silent-login, or bearer-only protected-request path.
- Expiry or any protected-request authentication failure clears protected state and returns to the credential form.
- Password state is overwritten and cleared immediately after the login body is serialized.
- The TPM private key remains non-exportable in Microsoft Platform Crypto Provider and signing-only.
- The first protected request is `/v1/me`; the dashboard opens only after that proof-bound response succeeds.

## Access-token verification

The JOSE header is exactly `alg=EdDSA`, `typ=JWT`, and a recognized `kid`. A compile-time key ring maps each accepted `kid` to one 32-byte Ed25519 public key. The payload requires `iss`, `aud`, `sub`, `app`, `product_id`, `product`, `license_id`, `device_id`, `sid`, `jti`, `iat`, `nbf`, `exp`, `features`, and `cnf.jkt`. StarLoader rejects duplicate JSON members, non-canonical base64url, unexpected critical header shapes, wrong application/product/device/license, and any lifetime other than 600 seconds.

## TPM DPoP proof

For every protected request StarLoader builds a compact ES256 JWS. The header is exactly `typ=dpop+jwt`, `alg=ES256`, and the public P-256 JWK. The payload contains a random 128-bit base64url `jti`, uppercase `htm`, canonical absolute HTTPS `htu` without query/fragment, current `iat`, and `ath` as base64url SHA-256 of the exact ASCII access token.

The public CNG blob is accepted only when it is a `BCRYPT_ECDSA_PUBLIC_P256_MAGIC` blob with 32-byte X and Y coordinates. The JWK thumbprint is RFC 7638 SHA-256 over canonical `{"crv":"P-256","kty":"EC","x":"...","y":"..."}`. It must match the token's `cnf.jkt`. CNG's fixed-width 64-byte `r || s` signature is used directly as the JWS signature.

Protected calls use `Authorization: DPoP <access-token>` and exactly one `DPoP` header. Proof generation failure prevents the request from being sent.

## Session lifecycle

`AuthManager` owns a single-shot timer scheduled from the verified token expiry. Closing the program, signing out, timer expiry, invalid token/session/proof response, or profile failure overwrites and clears the token and all authenticated profile state. Token expiry emits a stable reauthentication reason and shows the credential window; it never calls a refresh endpoint.

## Selective virtualization

StarLoader owns `STARLOADER_VM_BEGIN/END` and `STARLOADER_MUTATE_BEGIN/END` macros. They are no-ops in development/tests. Protected release builds map them to VMProtect SDK markers and fail configuration if the SDK header/library or project configuration is missing.

Initial marker regions cover only deterministic coordination decisions: access-token claim policy, DPoP field/binding policy, and the transition from verified `/v1/me` response to authenticated state. Qt event loops, network transport, JSON parsing loops, OpenSSL, CNG calls, exception machinery, and whole functions containing unbounded attacker-controlled loops are not virtualized.

Virtualization is defense in depth; KeyStar remains authoritative. The release order is build/test, protect, protected smoke test, malware scan, Authenticode SHA-256 sign, RFC 3161 timestamp, signature verification, package.

## Production TLS pinning

Production builds retain normal Windows/Qt certificate and hostname validation and additionally require the configured KeyStar host's leaf certificate SPKI SHA-256 to match one of exactly two compile-time pins: current and staged-next. StarLoader derives the SPKI DER from the peer X.509 certificate and hashes it with SHA-256. TLS errors, redirects to another host, missing peer certificates, pin mismatch, and pin-policy initialization failure abort the request. Numeric loopback HTTP bypass exists only in the explicit local-development build and cannot be enabled at runtime in production.

## Deferred dependency

This client delivery is testable against fixtures before KeyStar enables the policy. Production activation remains fail-closed until KeyStar issues the 600-second `kid`/`sid`/`jti`/`nbf`/`cnf.jkt` token profile and verifies DPoP/replay state. No compatibility fallback to bearer-only access is added.
