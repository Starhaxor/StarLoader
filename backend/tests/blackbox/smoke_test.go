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
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/starloader/backend/internal/security"
)

func TestProductionServerLoginDeviceAndReplay(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("STARLOADER_SMOKE_BASE_URL"), "/")
	if baseURL == "" {
		t.Skip("STARLOADER_SMOKE_BASE_URL is not set")
	}
	email := requiredEnvironment(t, "STARLOADER_SMOKE_EMAIL")
	password := requiredEnvironment(t, "STARLOADER_SMOKE_PASSWORD")
	maxDevices, err := strconv.Atoi(requiredEnvironment(t, "STARLOADER_SMOKE_MAX_DEVICES"))
	if err != nil || maxDevices <= 0 {
		t.Fatal("STARLOADER_SMOKE_MAX_DEVICES is invalid")
	}
	publicKeyEncoded := requiredEnvironment(t, "STARLOADER_SMOKE_ED25519_PUBLIC_KEY")
	privateKeyEncoded := requiredEnvironment(t, "STARLOADER_SMOKE_ED25519_PRIVATE_KEY")
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

	profileResponse := getWithBearer(t, baseURL+"/v1/me", verified.Token)
	if profileResponse.status != http.StatusOK {
		t.Fatalf("profile status = %d body = %s", profileResponse.status, profileResponse.body)
	}
	assertUUIDv7(t, profileResponse.requestID)
	var profile struct {
		OK               bool   `json:"ok"`
		Email            string `json:"email"`
		AccountStatus    string `json:"account_status"`
		Product          string `json:"product"`
		LicenseStatus    string `json:"license_status"`
		LicenseExpiresAt string `json:"license_expires_at"`
		MaxDevices       int    `json:"max_devices"`
		DeviceID         string `json:"device_id"`
		DeviceStatus     string `json:"device_status"`
		SessionExpiresAt string `json:"session_expires_at"`
	}
	if err := json.Unmarshal(profileResponse.body, &profile); err != nil {
		t.Fatal(err)
	}
	if !profile.OK || profile.Email != email || profile.AccountStatus != "active" || profile.Product != claims.Product ||
		profile.LicenseStatus != "active" || profile.MaxDevices != maxDevices ||
		profile.DeviceID != verified.DeviceID || profile.DeviceID != claims.DeviceID || profile.DeviceStatus != "active" ||
		profile.SessionExpiresAt != claims.ExpiresAt.UTC().Format(time.RFC3339) {
		t.Fatalf("profile is not bound to the verified account, license, device, and session")
	}
	licenseExpiresAt, err := time.Parse(time.RFC3339, profile.LicenseExpiresAt)
	if err != nil || time.Until(licenseExpiresAt) < 23*time.Hour || time.Until(licenseExpiresAt) > 25*time.Hour {
		t.Fatal("profile license expiry does not match the one-day verification license")
	}
	assertExactJSONKeys(t, profileResponse.body, []string{
		"account_status", "device_id", "device_status", "email", "license_expires_at",
		"license_status", "max_devices", "ok", "product", "session_expires_at",
	})

	otherLicenseClaims := claims
	otherLicenseClaims.LicenseID = "00000000-0000-7000-8000-000000000001"
	otherLicenseToken := signedSessionToken(t, privateKeyEncoded, otherLicenseClaims)
	verifiedOtherLicenseClaims, err := verifier.Verify(otherLicenseToken)
	if err != nil || verifiedOtherLicenseClaims.LicenseID != otherLicenseClaims.LicenseID {
		t.Fatal("alternate-license token is not correctly signed and unexpired")
	}
	otherLicenseResponse := getWithBearer(t, baseURL+"/v1/me", otherLicenseToken)
	assertSessionTokenRejected(t, otherLicenseResponse)

	invalidResponse := getWithBearer(t, baseURL+"/v1/me", "invalid-session-token")
	assertSessionTokenRejected(t, invalidResponse)

	expiredClaims := claims
	expiredClaims.ExpiresAt = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	expiredClaims.IssuedAt = expiredClaims.ExpiresAt.Add(-time.Hour)
	expired := signedSessionToken(t, privateKeyEncoded, expiredClaims)
	expiredResponse := getWithBearer(t, baseURL+"/v1/me", expired)
	assertSessionTokenRejected(t, expiredResponse)

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

func getWithBearer(t *testing.T, url, token string) response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
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

func signedSessionToken(t *testing.T, privateKeyEncoded string, claims security.SessionClaims) string {
	t.Helper()
	privateKey, err := security.ParseEd25519PrivateKey(privateKeyEncoded)
	if err != nil {
		t.Fatal("smoke Ed25519 private key is invalid")
	}
	headerJSON, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(map[string]any{
		"sub": claims.Subject, "license_id": claims.LicenseID, "device_id": claims.DeviceID,
		"product": claims.Product, "features": claims.Features, "iss": claims.Issuer, "aud": claims.Audience,
		"iat": claims.IssuedAt.Unix(), "exp": claims.ExpiresAt.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func assertSessionTokenRejected(t *testing.T, result response) {
	t.Helper()
	if result.status != http.StatusUnauthorized {
		t.Fatalf("session-token rejection status = %d", result.status)
	}
	assertUUIDv7(t, result.requestID)
	var errorResponse struct {
		OK        bool   `json:"ok"`
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(result.body, &errorResponse); err != nil {
		t.Fatalf("decode session-token rejection: %v", err)
	}
	assertExactJSONKeys(t, result.body, []string{"code", "message", "ok", "request_id"})
	if errorResponse.OK || errorResponse.Code != "INVALID_SESSION_TOKEN" || errorResponse.Message != "invalid session token" {
		t.Fatal("session-token rejection values are not the exact safe contract")
	}
	if errorResponse.RequestID != result.requestID {
		t.Fatal("session-token rejection header/body request IDs do not match")
	}
}

func assertExactJSONKeys(t *testing.T, body []byte, want []string) {
	t.Helper()
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(decoded))
	for key := range decoded {
		got = append(got, key)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("response keys = %v, want exact safe keys %v", got, want)
	}
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
