package security

import "testing"

func TestHMACHexUsesSHA256(t *testing.T) {
	got := HMACHex([]byte("key"), "The quick brown fox jumps over the lazy dog")
	const want = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
	if got != want {
		t.Fatalf("HMACHex() = %q, want %q", got, want)
	}
}
