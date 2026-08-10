package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// HMACHex returns the SHA-256 HMAC of an already-normalized value.
func HMACHex(secret []byte, normalized string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil))
}
