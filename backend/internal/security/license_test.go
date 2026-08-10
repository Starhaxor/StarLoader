package security

import (
	"bytes"
	"testing"
)

func TestNormalizeLicense(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "removes separators and uppercases", in: " abcd-ef12 ", want: "ABCDEF12"},
		{name: "removes whitespace and hyphens", in: "12 34-ab cd", want: "1234ABCD"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeLicense(tt.in); got != tt.want {
				t.Fatalf("NormalizeLicense(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestGenerateLicenseFormatsRandomBytes(t *testing.T) {
	plain, normalized, err := GenerateLicense(bytes.NewReader([]byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if plain != "01234567-89ABCDEF-FEDCBA98-76543210" {
		t.Fatalf("plain = %q", plain)
	}
	if normalized != "0123456789ABCDEFFEDCBA9876543210" {
		t.Fatalf("normalized = %q", normalized)
	}
}
