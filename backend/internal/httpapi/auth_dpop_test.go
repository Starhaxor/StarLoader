package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/starloader/backend/internal/security"
)

type testReplayStore struct {
	sync.Mutex
	seen map[[32]byte]bool
}

func (s *testReplayStore) ConsumeDPoP(_ context.Context, digest [32]byte, _ time.Time) (bool, error) {
	s.Lock()
	defer s.Unlock()
	if s.seen[digest] {
		return false, nil
	}
	s.seen[digest] = true
	return true, nil
}

func TestRequireSessionVerifiesBindingAndRejectsReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	x, y := make([]byte, 32), make([]byte, 32)
	device.X.FillBytes(x)
	device.Y.FillBytes(y)
	jwk := map[string]string{"kty": "EC", "crv": "P-256", "x": encode(x), "y": encode(y)}
	jwkJSON, _ := json.Marshal(jwk)
	_, thumb, err := security.ParseP256JWK(jwkJSON)
	if err != nil {
		t.Fatal(err)
	}
	policy := security.TokenPolicy{KeyID: "test", ApplicationID: "app", ProductID: "product"}
	issuer, err := security.NewTokenIssuer(priv, "issuer", "audience", "StarLoader", policy)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := security.NewTokenVerifier(pub, "issuer", "audience", "StarLoader", policy)
	if err != nil {
		t.Fatal(err)
	}
	claims := security.SessionClaims{ApplicationID: "app", ProductID: "product", Subject: "user", LicenseID: "license", DeviceID: "device", Product: "StarLoader", Issuer: "issuer", Audience: "audience", Features: []string{}, IssuedAt: now, ExpiresAt: now.Add(600 * time.Second), ProofBound: &security.ProofBoundClaims{SessionID: "session", TokenID: encode(make([]byte, 16)), DeviceKeyThumbprint: thumb, NotBefore: now}}
	token, err := issuer.Issue(claims)
	if err != nil {
		t.Fatal(err)
	}
	ath := sha256.Sum256([]byte(token))
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk})
	payload, _ := json.Marshal(map[string]any{"htm": "GET", "htu": "https://api.example.com/v1/me", "ath": encode(ath[:]), "iat": now.Unix(), "jti": encode(make([]byte, 16))})
	input := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, device, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	proof := input + "." + encode(signature)
	called := 0
	handler := RequireSession(verifier, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := SessionClaimsFromContext(r.Context())
		if !ok || got.Subject != claims.Subject || got.ProofBound.DeviceKeyThumbprint != thumb {
			t.Error("verified binding lost")
		}
		called++
		w.WriteHeader(204)
	}), SessionAuthConfig{PublicBaseURL: "https://api.example.com", Replays: &testReplayStore{seen: map[[32]byte]bool{}}})
	for _, tc := range []struct {
		scheme, path, proof string
		want                int
	}{
		{"Bearer", "/v1/me", proof, 401}, {"DPoP", "/v1/me", "", 401}, {"DPoP", "/other", proof, 401},
		{"DPoP", "/v1/me", proof, 204}, {"DPoP", "/v1/me", proof, 401},
	} {
		req := httptest.NewRequest("GET", tc.path, nil)
		req.Header.Set("Authorization", tc.scheme+" "+token)
		req.Header.Set("DPoP", tc.proof)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s got %d want %d", tc.scheme, tc.path, rec.Code, tc.want)
		}
	}
	if called != 1 {
		t.Fatalf("handler called %d times", called)
	}
}
