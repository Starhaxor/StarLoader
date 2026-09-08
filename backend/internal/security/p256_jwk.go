package security

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
)

// ErrInvalidDeviceJWK is the only error surfaced for TPM device-key parsing.
// It never reflects key material.
var ErrInvalidDeviceJWK = errors.New("invalid device key")

// maxDeviceJWKBytes caps the raw JWK document before any parsing work.
const maxDeviceJWKBytes = 16 * 1024

type p256JWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

// ParseP256JWK strictly parses a TPM P-256 public JWK and returns the public
// key with its RFC 7638 SHA-256 thumbprint. Only the exact member set
// {kty,crv,x,y} with kty=EC and crv=P-256 is accepted; x and y must be
// canonical base64url of 32 bytes each and form a valid P-256 curve point.
func ParseP256JWK(raw json.RawMessage) (*ecdsa.PublicKey, string, error) {
	if len(raw) == 0 || len(raw) > maxDeviceJWKBytes {
		return nil, "", ErrInvalidDeviceJWK
	}
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return nil, "", ErrInvalidDeviceJWK
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var key p256JWK
	if err := decoder.Decode(&key); err != nil {
		return nil, "", ErrInvalidDeviceJWK
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, "", ErrInvalidDeviceJWK
	}
	if key.KeyType != "EC" || key.Curve != "P-256" || key.X == "" || key.Y == "" {
		return nil, "", ErrInvalidDeviceJWK
	}
	x, ok := decodeP256Coordinate(key.X)
	if !ok {
		return nil, "", ErrInvalidDeviceJWK
	}
	y, ok := decodeP256Coordinate(key.Y)
	if !ok {
		return nil, "", ErrInvalidDeviceJWK
	}
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, "", ErrInvalidDeviceJWK
	}
	thumbprint := rfc7638ThumbprintSHA256(`{"crv":"P-256","kty":"EC","x":"` + key.X + `","y":"` + key.Y + `"}`)
	if !validCanonicalRandom(thumbprint, sha256.Size) {
		return nil, "", ErrInvalidDeviceJWK
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, thumbprint, nil
}

// decodeP256Coordinate decodes one canonical base64url 32-byte coordinate.
func decodeP256Coordinate(encoded string) (*big.Int, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != p256CoordinateBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, false
	}
	value := new(big.Int).SetBytes(decoded)
	if value.Sign() <= 0 || len(value.Bytes()) > p256CoordinateBytes {
		return nil, false
	}
	return value, true
}

// rfc7638ThumbprintSHA256 hashes an already-canonical required-members JSON
// object per RFC 7638 and returns the base64url SHA-256 thumbprint.
func rfc7638ThumbprintSHA256(canonical string) string {
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
