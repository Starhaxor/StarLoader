package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEd25519SessionTokenRoundTripPreservesRequiredClaims(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_786_350_600, 0).UTC()
	issuer, err := NewTokenIssuer(privateKey, "starloader", "starloader-client", "StarLoader")
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	verifier, err := NewTokenVerifier(publicKey, "starloader", "starloader-client", "StarLoader")
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	want := SessionClaims{
		Subject:   "user-1",
		LicenseID: "license-1",
		DeviceID:  "device-1",
		Product:   "StarLoader",
		Features:  []string{"launch"},
		Issuer:    "starloader",
		Audience:  "starloader-client",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}

	token, err := issuer.Issue(want)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if parts := strings.Split(token, "."); len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	got, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Verify() = %#v, want %#v", got, want)
	}
}

func TestTokenVerifierEnforcesIdentityAndExpiration(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_786_350_600, 0).UTC()
	claims := SessionClaims{
		Subject: "user-1", LicenseID: "license-1", DeviceID: "device-1",
		Product: "StarLoader", Issuer: "starloader", Audience: "starloader-client",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	issuer, err := NewTokenIssuer(privateKey, claims.Issuer, claims.Audience, claims.Product)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	token, err := issuer.Issue(claims)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		issuer   string
		audience string
		product  string
		now      time.Time
	}{
		{name: "wrong issuer", issuer: "other", audience: claims.Audience, product: claims.Product, now: now},
		{name: "wrong audience", issuer: claims.Issuer, audience: "other", product: claims.Product, now: now},
		{name: "wrong product", issuer: claims.Issuer, audience: claims.Audience, product: "Other", now: now},
		{name: "expired", issuer: claims.Issuer, audience: claims.Audience, product: claims.Product, now: claims.ExpiresAt},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := NewTokenVerifier(publicKey, test.issuer, test.audience, test.product)
			if err != nil {
				t.Fatal(err)
			}
			verifier.now = func() time.Time { return test.now }
			if _, err := verifier.Verify(token); err == nil {
				t.Fatal("Verify() accepted token outside policy")
			}
		})
	}
}

func TestTokenIssuerRejectsMissingLicenseOrDevice(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_786_350_600, 0).UTC()
	issuer, err := NewTokenIssuer(privateKey, "starloader", "client", "StarLoader")
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	valid := SessionClaims{
		Subject: "user", LicenseID: "license", DeviceID: "device", Product: "StarLoader",
		Issuer: "starloader", Audience: "client", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	for _, mutate := range []func(*SessionClaims){
		func(claims *SessionClaims) { claims.LicenseID = "" },
		func(claims *SessionClaims) { claims.DeviceID = "" },
	} {
		claims := valid
		mutate(&claims)
		if _, err := issuer.Issue(claims); err == nil {
			t.Fatal("Issue() accepted missing bound identity")
		}
	}
}

func TestTokenVerifierRejectsChangedSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_786_350_600, 0).UTC()
	issuer, _ := NewTokenIssuer(privateKey, "starloader", "client", "StarLoader")
	issuer.now = func() time.Time { return now }
	verifier, _ := NewTokenVerifier(publicKey, "starloader", "client", "StarLoader")
	verifier.now = func() time.Time { return now }
	token, err := issuer.Issue(SessionClaims{
		Subject: "user", LicenseID: "license", DeviceID: "device", Product: "StarLoader",
		Issuer: "starloader", Audience: "client", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(token)
	tampered[len(tampered)-1] ^= 1
	if _, err := verifier.Verify(string(tampered)); err == nil {
		t.Fatal("Verify() accepted changed signature")
	}
}

func TestEd25519ConfigurationRejectsInconsistentExpandedPrivateKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	malformed := append(ed25519.PrivateKey(nil), privateKey...)
	malformed[len(malformed)-1] ^= 0x80
	if _, err := NewTokenIssuer(malformed, "starloader", "client", "StarLoader"); err == nil {
		t.Fatal("NewTokenIssuer() accepted an inconsistent expanded private key")
	}
	encoded := base64.StdEncoding.EncodeToString(malformed)
	if _, err := ParseEd25519PrivateKey(encoded); err == nil {
		t.Fatal("ParseEd25519PrivateKey() accepted an inconsistent expanded private key")
	}
}

func TestTokenIssuerRequiresExactOneHourLifetime(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_786_350_600, 0).UTC()
	issuer, err := NewTokenIssuer(privateKey, "starloader", "client", "StarLoader")
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	for _, test := range []struct {
		name     string
		lifetime time.Duration
		wantOK   bool
	}{
		{name: "59 minutes", lifetime: 59 * time.Minute},
		{name: "exact hour", lifetime: time.Hour, wantOK: true},
		{name: "61 minutes", lifetime: 61 * time.Minute},
		{name: "one day", lifetime: 24 * time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := issuer.Issue(requiredTokenClaims(now, test.lifetime))
			if test.wantOK && err != nil {
				t.Fatalf("Issue() error = %v", err)
			}
			if !test.wantOK && err == nil {
				t.Fatalf("Issue() accepted lifetime %s", test.lifetime)
			}
		})
	}
}

func TestTokenVerifierRequiresExactOneHourLifetime(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_786_350_600, 0).UTC()
	verifier, err := NewTokenVerifier(publicKey, "starloader", "client", "StarLoader")
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	for _, test := range []struct {
		name     string
		lifetime time.Duration
		wantOK   bool
	}{
		{name: "59 minutes", lifetime: 59 * time.Minute},
		{name: "exact hour", lifetime: time.Hour, wantOK: true},
		{name: "61 minutes", lifetime: 61 * time.Minute},
		{name: "one day", lifetime: 24 * time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := signSessionClaimsForTest(t, privateKey, requiredTokenClaims(now, test.lifetime))
			_, err := verifier.Verify(token)
			if test.wantOK && err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if !test.wantOK && err == nil {
				t.Fatalf("Verify() accepted lifetime %s", test.lifetime)
			}
		})
	}
}

func requiredTokenClaims(issuedAt time.Time, lifetime time.Duration) SessionClaims {
	return SessionClaims{
		Subject: "user", LicenseID: "license", DeviceID: "device", Product: "StarLoader",
		Features: []string{}, Issuer: "starloader", Audience: "client",
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(lifetime),
	}
}

func signSessionClaimsForTest(t *testing.T, privateKey ed25519.PrivateKey, claims SessionClaims) string {
	t.Helper()
	headerJSON, err := json.Marshal(tokenHeader{Algorithm: "EdDSA", Type: "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(claimsToWire(claims))
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
