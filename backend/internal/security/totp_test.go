package security

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B vectors for SHA1 with the ASCII secret
// "12345678901234567890".
const rfcSecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPCodeMatchesRFC6238Vectors(t *testing.T) {
	tests := []struct {
		unixSeconds int64
		want        string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, test := range tests {
		at := time.Unix(test.unixSeconds, 0).UTC()
		code, err := TOTPCode(rfcSecretBase32, at)
		if err != nil {
			t.Fatalf("TOTPCode(%d) error = %v", test.unixSeconds, err)
		}
		if code != test.want {
			t.Fatalf("TOTPCode(%d) = %s, want %s", test.unixSeconds, code, test.want)
		}
	}
}

func TestValidateTOTPCodeAcceptsAdjacentSteps(t *testing.T) {
	at := time.Unix(1234567890, 0).UTC()
	current, err := TOTPCode(rfcSecretBase32, at)
	if err != nil {
		t.Fatalf("TOTPCode error = %v", err)
	}
	previous, err := TOTPCode(rfcSecretBase32, at.Add(-30*time.Second))
	if err != nil {
		t.Fatalf("TOTPCode previous error = %v", err)
	}
	next, err := TOTPCode(rfcSecretBase32, at.Add(30*time.Second))
	if err != nil {
		t.Fatalf("TOTPCode next error = %v", err)
	}
	for _, code := range []string{previous, current, next} {
		if !ValidateTOTPCode(rfcSecretBase32, code, at) {
			t.Fatalf("ValidateTOTPCode(%s) = false, want true", code)
		}
	}
}

func TestValidateTOTPCodeRejectsInvalidInput(t *testing.T) {
	at := time.Unix(1234567890, 0).UTC()
	if ValidateTOTPCode(rfcSecretBase32, "999999", at.Add(5*time.Minute)) {
		t.Fatal("stale code accepted")
	}
	if ValidateTOTPCode(rfcSecretBase32, "12345", at) {
		t.Fatal("short code accepted")
	}
	if ValidateTOTPCode("not-base32!!", "287082", at) {
		t.Fatal("invalid secret accepted")
	}
}

func TestGenerateTOTPSecretIsDecodableAndUnique(t *testing.T) {
	first, err := GenerateTOTPSecret(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateTOTPSecret error = %v", err)
	}
	second, err := GenerateTOTPSecret(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateTOTPSecret error = %v", err)
	}
	if first == second {
		t.Fatal("two generated secrets are identical")
	}
	if strings.Contains(first, "=") {
		t.Fatalf("secret contains padding: %s", first)
	}
	code, err := TOTPCode(first, time.Now())
	if err != nil || len(code) != 6 {
		t.Fatalf("generated secret unusable: code=%q err=%v", code, err)
	}
}

func TestTOTPProvisioningURIContainsSecretAndIssuer(t *testing.T) {
	uri := TOTPProvisioningURI(rfcSecretBase32, "root@example.com", "KeyStar Admin")
	for _, fragment := range []string{"otpauth://totp/", "secret=" + rfcSecretBase32, "issuer=KeyStar"} {
		if !strings.Contains(uri, fragment) {
			t.Fatalf("URI %q missing %q", uri, fragment)
		}
	}
}
