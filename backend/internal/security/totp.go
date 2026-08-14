package security

import (
	"crypto/hmac"
	"crypto/sha1"
	cryptorand "crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters follow RFC 6238 with the widely deployed authenticator
// defaults: 30 second steps, six digits, HMAC-SHA1.
const (
	totpPeriod     = 30 * time.Second
	totpDigits     = 6
	totpSecretSize = 20
	// totpDrift tolerates one step of clock skew in either direction.
	totpDrift = 1
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh base32 (unpadded) shared secret.
func GenerateTOTPSecret(random io.Reader) (string, error) {
	if random == nil {
		random = cryptorand.Reader
	}
	secret := make([]byte, totpSecretSize)
	if _, err := io.ReadFull(random, secret); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return totpBase32.EncodeToString(secret), nil
}

// TOTPCode derives the six digit code for the step containing at.
func TOTPCode(secret string, at time.Time) (string, error) {
	return totpCodeAtStep(secret, at.Unix()/int64(totpPeriod.Seconds()))
}

// ValidateTOTPCode accepts the code for the current step and one step of
// drift on either side. Comparison is constant time.
func ValidateTOTPCode(secret, code string, at time.Time) bool {
	key, err := totpBase32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return false
	}
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	step := at.Unix() / int64(totpPeriod.Seconds())
	for offset := -totpDrift; offset <= totpDrift; offset++ {
		candidate, err := hotpCode(key, step+int64(offset))
		if err != nil {
			continue
		}
		if hmac.Equal([]byte(candidate), []byte(code)) {
			return true
		}
	}
	return false
}

// TOTPProvisioningURI builds the otpauth:// URI consumed by authenticator
// apps.
func TOTPProvisioningURI(secret, accountName, issuer string) string {
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", issuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", fmt.Sprintf("%d", totpDigits))
	values.Set("period", fmt.Sprintf("%d", int(totpPeriod.Seconds())))
	label := url.PathEscape(issuer) + ":" + url.PathEscape(accountName)
	return "otpauth://totp/" + label + "?" + values.Encode()
}

func totpCodeAtStep(secret string, step int64) (string, error) {
	key, err := totpBase32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return "", fmt.Errorf("decode totp secret: %w", err)
	}
	return hotpCode(key, step)
}

// hotpCode implements RFC 4226 dynamic truncation.
func hotpCode(key []byte, counter int64) (string, error) {
	if counter < 0 {
		return "", fmt.Errorf("hotp counter must not be negative")
	}
	buffer := make([]byte, 8)
	binary.BigEndian.PutUint64(buffer, uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(buffer)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	value %= 1_000_000
	return fmt.Sprintf("%06d", value), nil
}
