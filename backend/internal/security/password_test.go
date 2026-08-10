package security

import "testing"

func TestPasswordRoundTrip(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(encoded, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(encoded, "incorrect password")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("wrong password was accepted")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	ok, err := VerifyPassword("not-an-argon2-hash", "password")
	if err == nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}
