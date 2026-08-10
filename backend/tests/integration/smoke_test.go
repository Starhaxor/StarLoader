package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/httpapi"
	"github.com/starloader/backend/internal/security"
	"github.com/starloader/backend/internal/service"
	"github.com/starloader/backend/internal/store"
)

func TestBlackBoxLoginDeviceAndReplaySmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)
	repository := store.New(pool)

	const (
		email      = "smoke@example.com"
		password   = "smoke-test-password"
		licenseKey = "01234567-89ABCDEF-FEDCBA98-76543210"
		product    = "StarLoader"
	)
	licenseHMACKey := []byte("smoke-license-hmac-key")
	hardwareHMACKey := []byte("smoke-hardware-hmac-key")
	passwordHash, err := security.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	user, err := repository.CreateUser(ctx, domain.NewUser{Email: email, PasswordHash: passwordHash})
	if err != nil {
		t.Fatal(err)
	}
	license, err := repository.CreateLicense(ctx, domain.NewLicense{
		LicenseHMAC: security.HMACHex(licenseHMACKey, security.NormalizeLicense(licenseKey)),
		UserID:      user.ID, Product: product, MaxDevices: 1, ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := security.NewTokenIssuer(privateKey, "starloader", "starloader-client", product)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := security.NewTokenVerifier(publicKey, "starloader", "starloader-client", product)
	if err != nil {
		t.Fatal(err)
	}
	loginService := service.NewLoginService(repository, licenseHMACKey, product)
	deviceService := service.NewDeviceService(service.NewStoreDeviceRepository(repository), service.DeviceServiceConfig{
		HardwareHMACKey: hardwareHMACKey, TokenIssuer: issuer,
		Issuer: "starloader", Audience: "starloader-client", Product: product,
	})
	server := httptest.NewServer(httpapi.NewRouter(httpapi.RouterConfig{
		Login: loginService, DeviceVerification: deviceService, HealthCheck: pool.Ping,
	}))
	defer server.Close()

	healthResponse, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer healthResponse.Body.Close()
	if healthResponse.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", healthResponse.StatusCode)
	}

	loginBody := map[string]any{
		"email": email, "password": password, "license_key": licenseKey,
		"device_fingerprint": "smoke-device-fingerprint",
	}
	loginResponse := postSmokeJSON(t, server.URL+"/v1/auth/login", loginBody)
	if loginResponse.status != http.StatusOK {
		t.Fatalf("login status = %d body = %s", loginResponse.status, loginResponse.body)
	}
	var pending struct {
		SessionID string `json:"session_id"`
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(loginResponse.body, &pending); err != nil {
		t.Fatal(err)
	}
	assertSmokeUUIDv7(t, pending.SessionID)
	challenge, err := base64.StdEncoding.DecodeString(pending.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	deviceKey := generateP256Key(t)
	publicBlob, signature := postgresCNGProof(t, deviceKey, challenge)
	verifyBody := map[string]any{
		"session_id": pending.SessionID, "challenge": pending.Challenge,
		"challenge_signature": base64.StdEncoding.EncodeToString(signature),
		"tpm_public_key":      base64.StdEncoding.EncodeToString(publicBlob),
		"hardware": map[string]string{
			"smbios_uuid": "smoke-smbios", "motherboard_serial": "smoke-board",
			"bios_serial": "smoke-bios", "system_disk_serial": "smoke-disk",
			"machine_guid": "smoke-guid", "fingerprint": "smoke-device-fingerprint",
		},
	}
	verificationResponse := postSmokeJSON(t, server.URL+"/v1/device/verify", verifyBody)
	if verificationResponse.status != http.StatusOK {
		t.Fatalf("device status = %d body = %s", verificationResponse.status, verificationResponse.body)
	}
	var verified struct {
		Token     string `json:"token"`
		LicenseID string `json:"license_id"`
		DeviceID  string `json:"device_id"`
	}
	if err := json.Unmarshal(verificationResponse.body, &verified); err != nil {
		t.Fatal(err)
	}
	assertSmokeUUIDv7(t, verified.LicenseID)
	assertSmokeUUIDv7(t, verified.DeviceID)
	claims, err := verifier.Verify(verified.Token)
	if err != nil {
		t.Fatalf("verify session token: %v", err)
	}
	if claims.Subject != user.ID || claims.LicenseID != license.ID || claims.DeviceID != verified.DeviceID {
		t.Fatalf("token claims = %#v", claims)
	}

	replayResponse := postSmokeJSON(t, server.URL+"/v1/device/verify", verifyBody)
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

type smokeResponse struct {
	status int
	body   []byte
}

func postSmokeJSON(t *testing.T, url string, value any) smokeResponse {
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
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var responseBody bytes.Buffer
	if _, err := responseBody.ReadFrom(response.Body); err != nil {
		t.Fatal(err)
	}
	return smokeResponse{status: response.StatusCode, body: responseBody.Bytes()}
}

func assertSmokeUUIDv7(t *testing.T, value string) {
	t.Helper()
	if len(value) != 36 || value[14] != '7' || (value[19] != '8' && value[19] != '9' && value[19] != 'a' && value[19] != 'b') {
		t.Fatalf("identifier %q is not canonical UUIDv7", value)
	}
}
