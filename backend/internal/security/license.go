package security

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// NormalizeLicense removes accepted display separators and uppercases a
// license. Validation belongs to the caller that knows the expected length.
func NormalizeLicense(license string) string {
	var normalized strings.Builder
	normalized.Grow(len(license))
	for _, r := range license {
		if r == '-' || unicode.IsSpace(r) {
			continue
		}
		normalized.WriteRune(unicode.ToUpper(r))
	}
	return normalized.String()
}

// GenerateLicense creates a 128-bit random license. The plaintext is intended
// only for one-time display; callers should persist normalized instead.
func GenerateLicense(random io.Reader) (plain, normalized string, err error) {
	if random == nil {
		return "", "", fmt.Errorf("license random reader is required")
	}
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(random, bytes); err != nil {
		return "", "", fmt.Errorf("read license randomness: %w", err)
	}
	hexadecimal := strings.ToUpper(hex.EncodeToString(bytes))
	plain = hexadecimal[0:8] + "-" + hexadecimal[8:16] + "-" + hexadecimal[16:24] + "-" + hexadecimal[24:32]
	return plain, NormalizeLicense(plain), nil
}
