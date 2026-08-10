# StarLoader Lisans API Sözleşmesi

Bu sözleşme istemci ve Go servisi arasındaki sürüm 1 protokolünü tanımlar. Üretimde yalnızca HTTPS kullanılır. Tüm JSON istekleri `Content-Type: application/json` taşır. Sunucu her yanıtta canonical, küçük harfli UUIDv7 biçiminde `X-Request-ID` üretir.

## `GET /healthz`

Başarılı yanıt (`200`):

```json
{"ok":true}
```

Veritabanı hazır değilse `503 SERVER_ERROR` döner.

## `POST /v1/auth/login`

İstek:

```json
{
  "email": "user@example.com",
  "password": "example-only",
  "license_key": "01234567-89ABCDEF-FEDCBA98-76543210",
  "device_fingerprint": "64-character-client-fingerprint"
}
```

Başarılı yanıt (`200`):

```json
{
  "ok": true,
  "session_id": "0198a123-4567-7abc-8def-0123456789ab",
  "challenge": "standard-base64-challenge",
  "challenge_expires_at": "2026-08-10T12:00:00Z"
}
```

`session_id` UUIDv7'dir. `challenge`, istemcinin TPM P-256 anahtarıyla SHA-256 üzerinden imzalayacağı 32 baytlık rastgele değerin standard Base64 gösterimidir.

## `POST /v1/device/verify`

İstek:

```json
{
  "session_id": "0198a123-4567-7abc-8def-0123456789ab",
  "challenge": "standard-base64-challenge",
  "challenge_signature": "standard-base64-raw-r-concat-s",
  "tpm_public_key": "standard-base64-bcrypt-eccpublic-blob",
  "hardware": {
    "smbios_uuid": "normalized-value",
    "motherboard_serial": "normalized-value",
    "bios_serial": "normalized-value",
    "system_disk_serial": "normalized-value",
    "machine_guid": "normalized-value",
    "fingerprint": "64-character-client-fingerprint"
  }
}
```

`tpm_public_key`, tam olarak Windows `BCRYPT_ECCPUBLIC_BLOB` P-256 biçimindedir. İmza, sabit genişlikli 32 bayt `r` ve 32 bayt `s` birleşimidir. Sunucu challenge'ın SHA-256 özetini doğrular.

Başarılı yanıt (`200`):

```json
{
  "ok": true,
  "token": "base64url-header.base64url-payload.base64url-signature",
  "token_expires_at": "2026-08-10T13:00:00Z",
  "license_id": "0198a123-4567-7abc-8def-0123456789ac",
  "device_id": "0198a123-4567-7abc-8def-0123456789ad"
}
```

Token Ed25519 ile imzalı, kompakt JWS biçimindedir. Başlık tam olarak `alg=EdDSA` ve `typ=JWT` taşır. Zorunlu claim'ler: `sub`, `license_id`, `device_id`, `product`, `features`, `iss`, `aud`, `iat`, `exp`. `exp - iat` tam 3600 saniyedir. İstemci imzayı ve tüm claim'leri kullanmadan önce doğrular.

## Hata biçimi

```json
{
  "ok": false,
  "code": "INVALID_CREDENTIALS",
  "message": "invalid credentials",
  "request_id": "0198a123-4567-7abc-8def-0123456789ae"
}
```

Tanımlı kodlar: `INVALID_REQUEST`, `INVALID_CREDENTIALS`, `LICENSE_NOT_FOUND`, `LICENSE_EXPIRED`, `LICENSE_REVOKED`, `CHALLENGE_EXPIRED`, `CHALLENGE_CONSUMED`, `INVALID_DEVICE_SIGNATURE`, `DEVICE_LIMIT_REACHED`, `DEVICE_REVOKED`, `RATE_LIMITED`, `SERVER_ERROR`.

Yanıt gövdeleri parola, lisans anahtarı, ham donanım verisi veya iç hata ayrıntısı içermez. Destek kayıtlarında yalnızca `request_id` kullanılmalıdır.
