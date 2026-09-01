# StarLoader protected-client activation

## Activation boundary

This repository's protected client is proof-ready. It is intentionally not
production-active until a matching KeyStar deployment is available. KeyStar
must issue access tokens with the strict 600-second profile accepted by the
client (`kid`, `sid`, `jti`, `nbf`, and `cnf.jkt`, as well as the configured
application/product/device/license bindings), require the TPM-bound ES256
DPoP proof on every protected request, and reject replayed proofs.

The client has no fallback to `Authorization: Bearer`, no refresh token, no
offline lease, and no runtime setting that enables a bearer-only protected
request. If the backend contract, DPoP validation, replay store, TLS pin
configuration, or proof generation is unavailable, the release must remain
blocked rather than weakening the client.

Unit and API tests verify the client-side contract without a deployed KeyStar
fixture. A live authentication proof is not evidence until the fixture or
production-like KeyStar instance implements this exact profile and validation
policy.

## Production configuration contract

Pass these values at CMake configure time through the deployment pipeline or
another protected build configuration. Do not commit private signing keys,
access tokens, passwords, DPoP proofs, or production pin values to the
repository.

| CMake cache variable | Required production format |
|---|---|
| `STARLOADER_API_URL` | Exact `https://<keystar-host>` base URL. Its host must exactly equal `STARLOADER_TLS_PINNED_HOST`. |
| `STARLOADER_TLS_PINNED_HOST` | Exact KeyStar DNS host, for example `<keystar-host>`; no scheme, path, or port. |
| `STARLOADER_TLS_SPKI_PINS` | Exactly two comma-separated, distinct pins: `sha256/<current-spki-sha256-standard-base64>,sha256/<staged-next-spki-sha256-standard-base64>`. Each decoded digest is exactly 32 bytes. |
| `STARLOADER_ED25519_KEY_RING` | One or more comma-separated entries: `<kid>=<32-byte-ed25519-public-key-standard-base64>[,<next-kid>=<32-byte-ed25519-public-key-standard-base64>]`. `kid` values are unique and use only letters, digits, `.`, `_`, or `-`. |
| `STARLOADER_APPLICATION_ID` | Canonical KeyStar application UUID. |
| `STARLOADER_PRODUCT_ID` | Configured product identifier. |
| `STARLOADER_PUBLISHABLE_KEY` | Deployment's KeyStar publishable key; it is not a private signing key. |

The standard Base64 values above use normal Base64 alphabet and padding, not
Base64URL. The pin list is deliberately a current plus staged-next pair; a
single pin, three pins, duplicate pins, malformed pins, or a host mismatch
fails configuration. The checked-in production preset intentionally has no
pins and must fail until the deployment pipeline supplies both pins.

For a protected release, configure Release mode and all three VMProtect inputs:

```powershell
cmake --preset qt-mingw-protected `
  -DSTARLOADER_API_URL=https://<keystar-host> `
  -DSTARLOADER_TLS_PINNED_HOST=<keystar-host> `
  -DSTARLOADER_TLS_SPKI_PINS='sha256/<current-spki-sha256-standard-base64>,sha256/<staged-next-spki-sha256-standard-base64>' `
  -DSTARLOADER_ED25519_KEY_RING='<kid>=<32-byte-ed25519-public-key-standard-base64>' `
  -DSTARLOADER_APPLICATION_ID=<canonical-application-uuid> `
  -DSTARLOADER_PRODUCT_ID=<product-id> `
  -DSTARLOADER_PUBLISHABLE_KEY=<keystar-publishable-key> `
  -DSTARLOADER_VMPROTECT_SDK_INCLUDE_DIR='<VMProtect-SDK-include-directory-containing-VMProtectSDK.h>' `
  -DSTARLOADER_VMPROTECT_SDK_LIBRARY='<VMProtect-SDK-library-file>' `
  -DSTARLOADER_VMPROTECT_PROJECT_FILE='<VMProtect-project-file>'
cmake --build --preset qt-mingw-protected
```

`STARLOADER_PROTECTED_RELEASE=ON` is supplied by the protected preset and is
valid only for `Release`. It fails configuration if the SDK include directory
does not contain `VMProtectSDK.h`, if the SDK library/project file is missing,
or if the build type is not Release. Keep these proprietary inputs outside the
repository and provide them through the protected build environment.

## Required release order

1. Deploy KeyStar first with the strict 600-second token profile, DPoP
   validation, token confirmation-key binding, and durable replay rejection.
   Verify it rejects bearer-only protected requests.
2. Provision and protect the KeyStar application signing keys; publish the
   matching public key ring to the client build as `kid=base64` entries. Keep
   private signing material only in the backend secret store.
3. Obtain the KeyStar TLS leaf-certificate SPKI SHA-256 values and configure
   exactly two distinct pins: the current pin and the staged-next rotation pin.
4. Configure the protected Release build, build every target, and run the full
   test suite before applying binary protection.
5. Process the release executable using the reviewed VMProtect project that
   corresponds to the supplied SDK inputs. Archive the project/version and
   build provenance with the release.
6. Run protected-binary smoke tests against the matching KeyStar fixture:
   successful proof-bound authentication; expiry requiring credentials again;
   DPoP replay rejection; malformed/missing proof rejection; bearer-only
   rejection; and current/staged pin acceptance plus wrong-pin and
   cross-host-pin failure.
7. Run the organization's malware scan on the protected artifacts and resolve
   findings before signing.
8. Authenticode-sign the scanned artifacts with SHA-256 and an RFC 3161
   timestamp.
9. Verify the final Authenticode signature, certificate chain, digest, and
   timestamp on the exact files that will be packaged.

## VMProtect scope and limits

VMProtect markers are limited to deterministic coordination decisions:

- access-token claim-policy acceptance;
- DPoP field and binding composition; and
- the transition from a verified `/v1/me` response to authenticated state.

The release deliberately does not virtualize Qt event loops, network transport,
JSON or Base64 parsing loops, OpenSSL, CNG/TPM operations, exception machinery,
or broad functions containing unbounded attacker-controlled loops. Those
regions are reliability- and performance-sensitive, and virtualizing them
would not improve the proof contract.

VMProtect obfuscation raises reverse-engineering and patching cost; it is not
cryptographic protection and cannot replace KeyStar authorization, TPM proof,
replay validation, normal TLS verification, certificate pinning, signing, or
malware controls.

## Verification boundary

The local `qt-mingw-local` preset is the reproducible client verification
baseline:

```powershell
cmake --preset qt-mingw-local
cmake --build --preset qt-mingw-local
ctest --preset qt-mingw-local --output-on-failure
```

The live native-flow test is intentionally skipped unless its configured
environment supplies a matching proof-enabled KeyStar fixture. A skip means
only that the external fixture dependency was unavailable; it must not be
reported as a passed production proof flow or used to justify a bearer
fallback. The client unit/API coverage and protected configuration tests remain
mandatory in either case.
