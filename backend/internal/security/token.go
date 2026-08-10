package security

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const maxSessionTokenBytes = 16 * 1024

var ErrInvalidSessionToken = errors.New("invalid session token")

type SessionClaims struct {
	Subject   string
	LicenseID string
	DeviceID  string
	Product   string
	Features  []string
	Issuer    string
	Audience  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type TokenIssuer struct {
	privateKey ed25519.PrivateKey
	issuer     string
	audience   string
	product    string
	now        func() time.Time
}

type TokenVerifier struct {
	publicKey ed25519.PublicKey
	issuer    string
	audience  string
	product   string
	now       func() time.Time
}

type tokenHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type sessionClaimsWire struct {
	Subject   string   `json:"sub"`
	LicenseID string   `json:"license_id"`
	DeviceID  string   `json:"device_id"`
	Product   string   `json:"product"`
	Features  []string `json:"features"`
	Issuer    string   `json:"iss"`
	Audience  string   `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

func NewTokenIssuer(privateKey ed25519.PrivateKey, issuer, audience, product string) (*TokenIssuer, error) {
	if !validEd25519PrivateKey(privateKey) || !validTokenPolicy(issuer, audience, product) {
		return nil, errors.New("invalid token issuer configuration")
	}
	return &TokenIssuer{
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		issuer:     issuer, audience: audience, product: product, now: time.Now,
	}, nil
}

func NewTokenVerifier(publicKey ed25519.PublicKey, issuer, audience, product string) (*TokenVerifier, error) {
	if len(publicKey) != ed25519.PublicKeySize || !validTokenPolicy(issuer, audience, product) {
		return nil, errors.New("invalid token verifier configuration")
	}
	return &TokenVerifier{
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
		issuer:    issuer, audience: audience, product: product, now: time.Now,
	}, nil
}

func ParseEd25519PrivateKey(encoded string) (ed25519.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, errors.New("ED25519_PRIVATE_KEY must be standard base64")
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		privateKey := ed25519.PrivateKey(append([]byte(nil), decoded...))
		if !validEd25519PrivateKey(privateKey) {
			return nil, errors.New("ED25519_PRIVATE_KEY contains an inconsistent public key")
		}
		return privateKey, nil
	default:
		return nil, fmt.Errorf("ED25519_PRIVATE_KEY must decode to %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func (issuer *TokenIssuer) Issue(claims SessionClaims) (string, error) {
	if issuer == nil || issuer.now == nil || len(issuer.privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("token issuer is not configured")
	}
	now := issuer.now().UTC()
	if err := validateClaims(claims, issuer.issuer, issuer.audience, issuer.product, now); err != nil {
		return "", err
	}
	headerJSON, err := json.Marshal(tokenHeader{Algorithm: "EdDSA", Type: "JWT"})
	if err != nil {
		return "", fmt.Errorf("encode token header: %w", err)
	}
	payloadJSON, err := json.Marshal(claimsToWire(claims))
	if err != nil {
		return "", fmt.Errorf("encode token claims: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	signature := ed25519.Sign(issuer.privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (verifier *TokenVerifier) Verify(token string) (SessionClaims, error) {
	if verifier == nil || verifier.now == nil || len(verifier.publicKey) != ed25519.PublicKeySize || len(token) == 0 || len(token) > maxSessionTokenBytes {
		return SessionClaims{}, ErrInvalidSessionToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return SessionClaims{}, ErrInvalidSessionToken
	}
	headerJSON, err := decodeTokenSegment(parts[0])
	if err != nil {
		return SessionClaims{}, ErrInvalidSessionToken
	}
	var header tokenHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil || header.Algorithm != "EdDSA" || header.Type != "JWT" {
		return SessionClaims{}, ErrInvalidSessionToken
	}
	signature, err := decodeTokenSegment(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(verifier.publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return SessionClaims{}, ErrInvalidSessionToken
	}
	payloadJSON, err := decodeTokenSegment(parts[1])
	if err != nil {
		return SessionClaims{}, ErrInvalidSessionToken
	}
	var wire sessionClaimsWire
	if err := json.Unmarshal(payloadJSON, &wire); err != nil {
		return SessionClaims{}, ErrInvalidSessionToken
	}
	claims := wireToClaims(wire)
	if err := validateClaims(claims, verifier.issuer, verifier.audience, verifier.product, verifier.now().UTC()); err != nil {
		return SessionClaims{}, ErrInvalidSessionToken
	}
	return claims, nil
}

func decodeTokenSegment(segment string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != segment {
		return nil, ErrInvalidSessionToken
	}
	return decoded, nil
}

func validTokenPolicy(issuer, audience, product string) bool {
	return strings.TrimSpace(issuer) != "" && strings.TrimSpace(audience) != "" && strings.TrimSpace(product) != ""
}

func validEd25519PrivateKey(privateKey ed25519.PrivateKey) bool {
	if len(privateKey) != ed25519.PrivateKeySize {
		return false
	}
	expected := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	return subtle.ConstantTimeCompare(privateKey[ed25519.SeedSize:], expected[ed25519.SeedSize:]) == 1
}

func validateClaims(claims SessionClaims, issuer, audience, product string, now time.Time) error {
	if claims.Subject == "" || claims.LicenseID == "" || claims.DeviceID == "" ||
		claims.Issuer != issuer || claims.Audience != audience || claims.Product != product ||
		claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || claims.IssuedAt.After(now) ||
		!claims.ExpiresAt.After(now) || !claims.ExpiresAt.After(claims.IssuedAt) ||
		claims.ExpiresAt.Sub(claims.IssuedAt) != time.Hour {
		return ErrInvalidSessionToken
	}
	return nil
}

func claimsToWire(claims SessionClaims) sessionClaimsWire {
	return sessionClaimsWire{
		Subject: claims.Subject, LicenseID: claims.LicenseID, DeviceID: claims.DeviceID,
		Product: claims.Product, Features: claims.Features, Issuer: claims.Issuer,
		Audience: claims.Audience, IssuedAt: claims.IssuedAt.Unix(), ExpiresAt: claims.ExpiresAt.Unix(),
	}
}

func wireToClaims(wire sessionClaimsWire) SessionClaims {
	return SessionClaims{
		Subject: wire.Subject, LicenseID: wire.LicenseID, DeviceID: wire.DeviceID,
		Product: wire.Product, Features: wire.Features, Issuer: wire.Issuer,
		Audience: wire.Audience, IssuedAt: time.Unix(wire.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(wire.ExpiresAt, 0).UTC(),
	}
}
