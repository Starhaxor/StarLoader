package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"
)

func TestVerifyCNGP256AcceptsRawWindowsSignature(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("single-use challenge")
	digest := sha256.Sum256(challenge)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyCNGP256(cngP256Blob(&privateKey.PublicKey), challenge, rawP256Signature(r, s)); err != nil {
		t.Fatalf("VerifyCNGP256() error = %v", err)
	}
}

func TestVerifyCNGP256RejectsInvalidProofs(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("single-use challenge")
	digest := sha256.Sum256(challenge)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	blob := cngP256Blob(&privateKey.PublicKey)
	signature := rawP256Signature(r, s)

	tests := []struct {
		name      string
		blob      []byte
		challenge []byte
		signature []byte
	}{
		{name: "wrong challenge", blob: blob, challenge: []byte("different"), signature: signature},
		{name: "changed signature", blob: blob, challenge: challenge, signature: append([]byte(nil), signature...)},
		{name: "wrong blob magic", blob: append([]byte(nil), blob...), challenge: challenge, signature: signature},
		{name: "short blob", blob: blob[:len(blob)-1], challenge: challenge, signature: signature},
		{name: "short signature", blob: blob, challenge: challenge, signature: signature[:len(signature)-1]},
	}
	tests[1].signature[0] ^= 0x80
	tests[2].blob[0] ^= 0x01
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyCNGP256(test.blob, test.challenge, test.signature); err == nil {
				t.Fatal("VerifyCNGP256() accepted invalid proof")
			}
		})
	}
}

func cngP256Blob(publicKey *ecdsa.PublicKey) []byte {
	blob := make([]byte, 8+2*32)
	binary.LittleEndian.PutUint32(blob[0:4], 0x31534345)
	binary.LittleEndian.PutUint32(blob[4:8], 32)
	publicKey.X.FillBytes(blob[8:40])
	publicKey.Y.FillBytes(blob[40:72])
	return blob
}

func rawP256Signature(r, s *big.Int) []byte {
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature
}
