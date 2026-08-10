package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

const (
	cngECDSAPublicP256Magic = 0x31534345
	p256CoordinateBytes     = 32
	cngP256PublicBlobBytes  = 8 + 2*p256CoordinateBytes
	rawP256SignatureBytes   = 2 * p256CoordinateBytes
)

var ErrInvalidDeviceProof = errors.New("invalid device proof")

// VerifyCNGP256 verifies the byte formats emitted by Windows CNG: an exact
// BCRYPT_ECCPUBLIC_BLOB containing an ECDSA P-256 public key and the raw,
// fixed-width r||s signature returned by NCryptSignHash.
func VerifyCNGP256(publicBlob, challenge, signature []byte) error {
	if len(publicBlob) != cngP256PublicBlobBytes || len(challenge) == 0 || len(signature) != rawP256SignatureBytes {
		return ErrInvalidDeviceProof
	}
	if binary.LittleEndian.Uint32(publicBlob[:4]) != cngECDSAPublicP256Magic || binary.LittleEndian.Uint32(publicBlob[4:8]) != p256CoordinateBytes {
		return ErrInvalidDeviceProof
	}

	x := new(big.Int).SetBytes(publicBlob[8:40])
	y := new(big.Int).SetBytes(publicBlob[40:72])
	curve := elliptic.P256()
	if x.Sign() == 0 || y.Sign() == 0 || !curve.IsOnCurve(x, y) {
		return ErrInvalidDeviceProof
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(curve.Params().N) >= 0 || s.Cmp(curve.Params().N) >= 0 {
		return ErrInvalidDeviceProof
	}
	digest := sha256.Sum256(challenge)
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, digest[:], r, s) {
		return ErrInvalidDeviceProof
	}
	return nil
}
