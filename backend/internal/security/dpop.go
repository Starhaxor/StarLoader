package security

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// ErrInvalidDPoPProof is the only error surfaced for DPoP verification. It
// never reflects tokens, proofs, coordinates, or raw identifiers.
var ErrInvalidDPoPProof = errors.New("invalid proof")

// dpopClockSkew bounds proof freshness around the server clock.
const dpopClockSkew = 60 * time.Second

// DPoPInput carries a compact DPoP proof with the server-built request
// context it must match. URI is the canonical absolute request URI without
// query or fragment; Token holds the verified proof-bound session claims.
type DPoPInput struct {
	Proof       string
	AccessToken string
	Method      string
	URI         string
	Token       SessionClaims
	Now         time.Time
}

// ProofClaims is the verified outcome of a DPoP proof. Only the SHA-256 of
// the canonical proof identifier leaves this boundary, never the raw jti.
type ProofClaims struct {
	JTIDigest     [32]byte
	IssuedAt      time.Time
	KeyThumbprint string
}

type dpopHeaderWire struct {
	Algorithm string          `json:"alg"`
	Type      string          `json:"typ"`
	JWK       json.RawMessage `json:"jwk"`
}

type dpopPayloadWire struct {
	Method     string `json:"htm"`
	URI        string `json:"htu"`
	AccessHash string `json:"ath"`
	IssuedAt   int64  `json:"iat"`
	TokenID    string `json:"jti"`
}

// VerifyDPoP performs the stateless DPoP checks for a proof-bound session:
// exact dpop+jwt/ES256 header with an embedded P-256 JWK bound to the token
// thumbprint, canonical 64-byte r||s signature, method and normalized URI
// binding, access-token hash binding, freshness within clock skew and token
// expiry, and a canonical 128-bit proof identifier.
func VerifyDPoP(input DPoPInput) (ProofClaims, error) {
	now := input.Now.UTC()
	if input.Now.IsZero() {
		now = time.Now().UTC()
	}
	if len(input.Proof) == 0 || len(input.Proof) > maxSessionTokenBytes ||
		len(input.AccessToken) == 0 || len(input.AccessToken) > maxSessionTokenBytes ||
		strings.TrimSpace(input.Method) == "" || input.Token.ProofBound == nil {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	parts, decoded, err := decodeCompactToken(input.Proof)
	if err != nil {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	var header dpopHeaderWire
	if err := decodeStrictJSONObject(decoded[0], &header); err != nil ||
		header.Algorithm != "ES256" || header.Type != "dpop+jwt" || len(header.JWK) == 0 {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	deviceKey, thumbprint, err := ParseP256JWK(header.JWK)
	if err != nil {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	if len(thumbprint) != len(input.Token.ProofBound.DeviceKeyThumbprint) ||
		subtle.ConstantTimeCompare([]byte(thumbprint), []byte(input.Token.ProofBound.DeviceKeyThumbprint)) != 1 {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	if err := verifyCompactECDSASignature(deviceKey, parts[0]+"."+parts[1], decoded[2]); err != nil {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	var payload dpopPayloadWire
	if err := decodeStrictJSONObject(decoded[1], &payload); err != nil {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	if payload.Method == "" || payload.Method != strings.ToUpper(input.Method) {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	if !validAbsoluteDPoPURI(payload.URI) || !validAbsoluteDPoPURI(input.URI) ||
		len(payload.URI) != len(input.URI) ||
		subtle.ConstantTimeCompare([]byte(payload.URI), []byte(input.URI)) != 1 {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	expectedATH := accessTokenHash(input.AccessToken)
	if !validCanonicalRandom(payload.AccessHash, sha256.Size) ||
		subtle.ConstantTimeCompare([]byte(payload.AccessHash), []byte(expectedATH)) != 1 {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	if payload.IssuedAt <= 0 {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	issuedAt := time.Unix(payload.IssuedAt, 0).UTC()
	if issuedAt.After(now.Add(dpopClockSkew)) || issuedAt.Before(now.Add(-dpopClockSkew)) ||
		!issuedAt.Before(input.Token.ExpiresAt) {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	if !validCanonicalRandom(payload.TokenID, 16) {
		return ProofClaims{}, ErrInvalidDPoPProof
	}
	return ProofClaims{
		JTIDigest:     sha256.Sum256([]byte(payload.TokenID)),
		IssuedAt:      issuedAt,
		KeyThumbprint: thumbprint,
	}, nil
}

// verifyCompactECDSASignature verifies a canonical 64-byte r||s signature
// over the compact signing input and rejects DER or malformed encodings.
func verifyCompactECDSASignature(key *ecdsa.PublicKey, signingInput string, signature []byte) error {
	if key == nil || key.Curve == nil || len(signature) != 2*p256CoordinateBytes {
		return ErrInvalidDPoPProof
	}
	order := key.Curve.Params().N
	r := new(big.Int).SetBytes(signature[:p256CoordinateBytes])
	s := new(big.Int).SetBytes(signature[p256CoordinateBytes:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(order) >= 0 || s.Cmp(order) >= 0 {
		return ErrInvalidDPoPProof
	}
	digest := sha256.Sum256([]byte(signingInput))
	if !ecdsa.Verify(key, digest[:], r, s) {
		return ErrInvalidDPoPProof
	}
	return nil
}

// accessTokenHash returns the canonical base64url SHA-256 of the exact
// ASCII access token for ath comparison.
func accessTokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// validAbsoluteDPoPURI requires an absolute URI with host, without userinfo,
// query, or fragment. Normalization is the caller's duty; this only gates
// shape so comparisons stay exact.
func validAbsoluteDPoPURI(raw string) bool {
	if raw == "" || len(raw) > 8*1024 {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return false
	}
	return true
}
