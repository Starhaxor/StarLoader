package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const maxSessionTokenBytes = 16 * 1024

var ErrInvalidSessionToken = errors.New("invalid session token")

type TokenPolicy struct {
	KeyID         string
	ApplicationID string
	ProductID     string
}

type ProofBoundClaims struct {
	SessionID           string
	TokenID             string
	DeviceKeyThumbprint string
	NotBefore           time.Time
}

type SessionClaims struct {
	ApplicationID string
	ProductID     string
	ProofBound    *ProofBoundClaims
	Subject       string
	LicenseID     string
	DeviceID      string
	Product       string
	Features      []string
	Issuer        string
	Audience      string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

type TokenIssuer struct {
	policy     TokenPolicy
	privateKey ed25519.PrivateKey
	issuer     string
	audience   string
	product    string
	now        func() time.Time
}

type TokenVerifier struct {
	policy    TokenPolicy
	publicKey ed25519.PublicKey
	issuer    string
	audience  string
	product   string
	now       func() time.Time
}

type tokenHeader struct {
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type confirmationWire struct {
	JKT string `json:"jkt"`
}

type sessionClaimsWire struct {
	ApplicationID string           `json:"app"`
	ProductID     string           `json:"product_id"`
	SessionID     string           `json:"sid"`
	TokenID       string           `json:"jti"`
	NotBefore     int64            `json:"nbf"`
	Confirmation  confirmationWire `json:"cnf"`
	Subject       string           `json:"sub"`
	LicenseID     string           `json:"license_id"`
	DeviceID      string           `json:"device_id"`
	Product       string           `json:"product"`
	Features      []string         `json:"features"`
	Issuer        string           `json:"iss"`
	Audience      string           `json:"aud"`
	IssuedAt      int64            `json:"iat"`
	ExpiresAt     int64            `json:"exp"`
}

func NewTokenIssuer(privateKey ed25519.PrivateKey, issuer, audience, product string, policy TokenPolicy) (*TokenIssuer, error) {
	if !validEd25519PrivateKey(privateKey) || !validTokenPolicy(issuer, audience, product) || !validProofPolicy(policy) {
		return nil, errors.New("invalid token issuer configuration")
	}
	return &TokenIssuer{policy: policy,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		issuer:     issuer, audience: audience, product: product, now: time.Now,
	}, nil
}

func NewTokenVerifier(publicKey ed25519.PublicKey, issuer, audience, product string, policy TokenPolicy) (*TokenVerifier, error) {
	if len(publicKey) != ed25519.PublicKeySize || !validTokenPolicy(issuer, audience, product) || !validProofPolicy(policy) {
		return nil, errors.New("invalid token verifier configuration")
	}
	return &TokenVerifier{policy: policy,
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
	if err := validateClaims(claims, issuer.issuer, issuer.audience, issuer.product, issuer.policy, now); err != nil {
		return "", err
	}
	headerJSON, err := json.Marshal(tokenHeader{Algorithm: "EdDSA", Type: "JWT", KeyID: issuer.policy.KeyID})
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
	if err := decodeStrictJSONObject(headerJSON, &header); err != nil || header.Algorithm != "EdDSA" || header.Type != "JWT" || header.KeyID != verifier.policy.KeyID {
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
	if err := decodeStrictJSONObject(payloadJSON, &wire); err != nil {
		return SessionClaims{}, ErrInvalidSessionToken
	}
	claims := wireToClaims(wire)
	if err := validateClaims(claims, verifier.issuer, verifier.audience, verifier.product, verifier.policy, verifier.now().UTC()); err != nil {
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

func validateClaims(claims SessionClaims, issuer, audience, product string, policy TokenPolicy, now time.Time) error {
	if claims.ProofBound == nil {
		return ErrInvalidSessionToken
	}
	proof := claims.ProofBound
	if claims.ApplicationID != policy.ApplicationID || claims.ProductID != policy.ProductID || proof.SessionID == "" || !validCanonicalRandom(proof.TokenID, 16) || !validCanonicalRandom(proof.DeviceKeyThumbprint, 32) || !proof.NotBefore.Equal(claims.IssuedAt) || claims.IssuedAt.Nanosecond() != 0 || claims.ExpiresAt.Nanosecond() != 0 || claims.Subject == "" || claims.LicenseID == "" || claims.DeviceID == "" ||
		claims.Issuer != issuer || claims.Audience != audience || claims.Product != product ||
		claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || claims.IssuedAt.After(now) ||
		!claims.ExpiresAt.After(now) || !claims.ExpiresAt.After(claims.IssuedAt) ||
		claims.ExpiresAt.Sub(claims.IssuedAt) != 600*time.Second {
		return ErrInvalidSessionToken
	}
	return nil
}

func claimsToWire(claims SessionClaims) sessionClaimsWire {
	return sessionClaimsWire{
		ApplicationID: claims.ApplicationID, ProductID: claims.ProductID, SessionID: claims.ProofBound.SessionID, TokenID: claims.ProofBound.TokenID, NotBefore: claims.ProofBound.NotBefore.Unix(), Confirmation: confirmationWire{JKT: claims.ProofBound.DeviceKeyThumbprint},
		Subject: claims.Subject, LicenseID: claims.LicenseID, DeviceID: claims.DeviceID,
		Product: claims.Product, Features: claims.Features, Issuer: claims.Issuer,
		Audience: claims.Audience, IssuedAt: claims.IssuedAt.Unix(), ExpiresAt: claims.ExpiresAt.Unix(),
	}
}

func wireToClaims(wire sessionClaimsWire) SessionClaims {
	return SessionClaims{
		ApplicationID: wire.ApplicationID, ProductID: wire.ProductID, ProofBound: &ProofBoundClaims{SessionID: wire.SessionID, TokenID: wire.TokenID, NotBefore: time.Unix(wire.NotBefore, 0).UTC(), DeviceKeyThumbprint: wire.Confirmation.JKT},
		Subject: wire.Subject, LicenseID: wire.LicenseID, DeviceID: wire.DeviceID,
		Product: wire.Product, Features: wire.Features, Issuer: wire.Issuer,
		Audience: wire.Audience, IssuedAt: time.Unix(wire.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(wire.ExpiresAt, 0).UTC(),
	}
}

func validProofPolicy(p TokenPolicy) bool {
	return strings.TrimSpace(p.KeyID) != "" && strings.TrimSpace(p.ApplicationID) != "" && strings.TrimSpace(p.ProductID) != ""
}

func decodeCompactToken(token string) ([3]string, [3][]byte, error) {
	var parts [3]string
	var decoded [3][]byte
	if len(token) == 0 || len(token) > maxSessionTokenBytes {
		return parts, decoded, ErrInvalidSessionToken
	}
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return parts, decoded, ErrInvalidSessionToken
	}
	for index, segment := range split {
		if segment == "" {
			return parts, decoded, ErrInvalidSessionToken
		}
		value, err := decodeTokenSegment(segment)
		if err != nil {
			return parts, decoded, ErrInvalidSessionToken
		}
		parts[index], decoded[index] = segment, value
	}
	return parts, decoded, nil
}

func decodeStrictJSONObject(raw []byte, destination any) error {
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return ErrInvalidSessionToken
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidSessionToken
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidSessionToken
	}
	return nil
}

func rejectDuplicateJSONMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := readUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidSessionToken
	}
	return nil
}

func readUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidSessionToken
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		members := make(map[string]struct{})
		for decoder.More() {
			memberToken, err := decoder.Token()
			if err != nil {
				return ErrInvalidSessionToken
			}
			member, ok := memberToken.(string)
			if !ok {
				return ErrInvalidSessionToken
			}
			if _, exists := members[member]; exists {
				return ErrInvalidSessionToken
			}
			members[member] = struct{}{}
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidSessionToken
		}
	case '[':
		for decoder.More() {
			if err := readUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidSessionToken
		}
	default:
		return ErrInvalidSessionToken
	}
	return nil
}

func validCanonicalRandom(value string, size int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == size && base64.RawURLEncoding.EncodeToString(decoded) == value
}
