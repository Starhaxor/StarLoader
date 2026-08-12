package blackbox_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/starloader/backend/internal/security"
)

func TestProductionServerLoginDeviceAndReplay(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("STARLOADER_SMOKE_BASE_URL"), "/")
	if baseURL == "" {
		t.Skip("STARLOADER_SMOKE_BASE_URL is not set")
	}
	email := requiredEnvironment(t, "STARLOADER_SMOKE_EMAIL")
	password := requiredEnvironment(t, "STARLOADER_SMOKE_PASSWORD")
	publicKeyEncoded := requiredEnvironment(t, "STARLOADER_SMOKE_ED25519_PUBLIC_KEY")
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyEncoded)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("smoke Ed25519 public key is invalid")
	}
	verifier, err := security.NewTokenVerifier(ed25519.PublicKey(publicKey), "starloader", "starloader-client", "StarLoader")
	if err != nil {
		t.Fatal(err)
	}

	healthResponse, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	healthResponse.Body.Close()
	if healthResponse.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", healthResponse.StatusCode)
	}

	loginResponse := postJSON(t, baseURL+"/v1/auth/login", map[string]any{
		"email": email, "password": password,
		"device_fingerprint": "blackbox-device-fingerprint",
	})
	if loginResponse.status != http.StatusOK {
		t.Fatalf("login status = %d body = %s", loginResponse.status, loginResponse.body)
	}
	assertUUIDv7(t, loginResponse.requestID)
	var pending struct {
		SessionID string `json:"session_id"`
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(loginResponse.body, &pending); err != nil {
		t.Fatal(err)
	}
	assertUUIDv7(t, pending.SessionID)
	challenge, err := base64.StdEncoding.DecodeString(pending.Challenge)
	if err != nil || len(challenge) != 32 {
		t.Fatal("server challenge is invalid")
	}
	publicBlob, signature := cngProof(t, challenge)
	verifyBody := map[string]any{
		"session_id": pending.SessionID, "challenge": pending.Challenge,
		"challenge_signature": base64.StdEncoding.EncodeToString(signature),
		"tpm_public_key":      base64.StdEncoding.EncodeToString(publicBlob),
		"hardware": map[string]string{
			"smbios_uuid": "blackbox-smbios", "motherboard_serial": "blackbox-board",
			"bios_serial": "blackbox-bios", "system_disk_serial": "blackbox-disk",
			"machine_guid": "blackbox-guid", "fingerprint": "blackbox-device-fingerprint",
		},
	}
	verificationResponse := postJSON(t, baseURL+"/v1/device/verify", verifyBody)
	if verificationResponse.status != http.StatusOK {
		t.Fatalf("device status = %d body = %s", verificationResponse.status, verificationResponse.body)
	}
	assertUUIDv7(t, verificationResponse.requestID)
	var verified struct {
		Token     string `json:"token"`
		LicenseID string `json:"license_id"`
		DeviceID  string `json:"device_id"`
	}
	if err := json.Unmarshal(verificationResponse.body, &verified); err != nil {
		t.Fatal(err)
	}
	assertUUIDv7(t, verified.LicenseID)
	assertUUIDv7(t, verified.DeviceID)
	claims, err := verifier.Verify(verified.Token)
	if err != nil {
		t.Fatalf("verify session token: %v", err)
	}
	if claims.LicenseID != verified.LicenseID || claims.DeviceID != verified.DeviceID || claims.Product != "StarLoader" {
		t.Fatalf("token binding does not match the response")
	}

	replayResponse := postJSON(t, baseURL+"/v1/device/verify", verifyBody)
	if replayResponse.status != http.StatusConflict {
		t.Fatalf("replay status = %d body = %s", replayResponse.status, replayResponse.body)
	}
	var replayError struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(replayResponse.body, &replayError); err != nil || replayError.Code != "CHALLENGE_CONSUMED" {
		t.Fatalf("replay error = %q parse error = %v", replayError.Code, err)
	}
}

type response struct {
	status    int
	body      []byte
	requestID string
}

func postJSON(t *testing.T, url string, value any) response {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	result, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	var responseBody bytes.Buffer
	if _, err := responseBody.ReadFrom(result.Body); err != nil {
		t.Fatal(err)
	}
	return response{status: result.StatusCode, body: responseBody.Bytes(), requestID: result.Header.Get("X-Request-ID")}
}

func cngProof(t *testing.T, challenge []byte) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 72)
	binary.LittleEndian.PutUint32(blob[:4], 0x31534345)
	binary.LittleEndian.PutUint32(blob[4:8], 32)
	key.X.FillBytes(blob[8:40])
	key.Y.FillBytes(blob[40:72])
	digest := sha256.Sum256(challenge)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return blob, signature
}

func requiredEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is not set", name)
	}
	return value
}

func assertUUIDv7(t *testing.T, value string) {
	t.Helper()
	if len(value) != 36 || value != strings.ToLower(value) || value[14] != '7' || !strings.ContainsRune("89ab", rune(value[19])) {
		t.Fatalf("identifier %q is not canonical UUIDv7", value)
	}
}
