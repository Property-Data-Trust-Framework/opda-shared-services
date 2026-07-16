package main

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

var (
	testKey = []byte("test-hmac-key-not-for-production")
	testNow = time.Unix(1_800_000_000, 0)
)

func init() {
	l = slog.New(slog.NewJSONHandler(os.Stderr, nil))
}

func TestMintVerifyRoundTrip(t *testing.T) {
	token := mintToken(testKey, "client-a", "land-registry epc", time.Hour, testNow)

	claims, err := verifyToken(testKey, token, testNow.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if claims.ClientID != "client-a" {
		t.Errorf("client_id = %q, want client-a", claims.ClientID)
	}
	if claims.Scope != "land-registry epc" {
		t.Errorf("scope = %q, want %q", claims.Scope, "land-registry epc")
	}
	if claims.Exp != testNow.Add(time.Hour).Unix() {
		t.Errorf("exp = %d, want %d", claims.Exp, testNow.Add(time.Hour).Unix())
	}
}

func TestVerifyExpired(t *testing.T) {
	token := mintToken(testKey, "client-a", "epc", time.Hour, testNow)
	if _, err := verifyToken(testKey, token, testNow.Add(2*time.Hour)); err != errExpired {
		t.Fatalf("err = %v, want errExpired", err)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	token := mintToken(testKey, "client-a", "epc", time.Hour, testNow)
	if _, err := verifyToken([]byte("different-key"), token, testNow); err != errBadMAC {
		t.Fatalf("err = %v, want errBadMAC", err)
	}
}

func TestVerifyTampered(t *testing.T) {
	token := mintToken(testKey, "client-a", "epc", time.Hour, testNow)
	for _, bad := range []string{
		"garbage",
		"no-dot-at-all",
		"!!!." + strings.Split(token, ".")[1],
		strings.Split(token, ".")[0] + ".!!!",
	} {
		if _, err := verifyToken(testKey, bad, testNow); err == nil {
			t.Errorf("verify(%q) succeeded, want error", bad)
		}
	}
}

func TestResolveScope(t *testing.T) {
	registered := []string{"land-registry", "epc"}

	tests := []struct {
		name      string
		requested string
		want      string
		wantErr   bool
	}{
		{"empty grants all", "", "land-registry epc", false},
		{"subset allowed", "epc", "epc", false},
		{"full set allowed", "land-registry epc", "land-registry epc", false},
		{"unregistered denied", "admin", "", true},
		{"mixed denied", "epc admin", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveScope(registered, tt.requested)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("scope = %q, want %q", got, tt.want)
			}
		})
	}
}

func testConfig() stubConfig {
	return stubConfig{
		clients: map[string]clientEntry{
			"demo-bff": {Scopes: []string{"land-registry", "epc"}},
		},
		hmacKey:  testKey,
		tokenTTL: time.Hour,
	}
}

func TestHandleTokenAndIntrospectionFlow(t *testing.T) {
	ctx := context.Background()
	c := testConfig()

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {"demo-bff"},
		"scope":                 {"land-registry"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {"ignored.by.design"},
	}
	resp := handleToken(ctx, c, form, testNow)
	if resp.StatusCode != 200 {
		t.Fatalf("token status = %d, body %s", resp.StatusCode, resp.Body)
	}
	if !strings.Contains(resp.Body, `"access_token"`) {
		t.Fatalf("no access_token in %s", resp.Body)
	}
	token := extractJSONField(t, resp.Body, "access_token")

	intro := handleIntrospection(ctx, c, url.Values{"token": {token}}, testNow.Add(time.Minute))
	if intro.StatusCode != 200 {
		t.Fatalf("introspection status = %d", intro.StatusCode)
	}
	for _, want := range []string{`"active":true`, `"client_id":"demo-bff"`, `"scope":"land-registry"`} {
		if !strings.Contains(intro.Body, want) {
			t.Errorf("introspection body missing %s: %s", want, intro.Body)
		}
	}
	if strings.Contains(intro.Body, "cnf") {
		t.Errorf("introspection must never return cnf: %s", intro.Body)
	}
}

func TestHandleTokenUnknownClient(t *testing.T) {
	resp := handleToken(context.Background(), testConfig(), url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"nobody"},
	}, testNow)
	if resp.StatusCode != 401 || !strings.Contains(resp.Body, "invalid_client") {
		t.Fatalf("status = %d body = %s, want 401 invalid_client", resp.StatusCode, resp.Body)
	}
}

func TestHandleTokenBadGrant(t *testing.T) {
	resp := handleToken(context.Background(), testConfig(), url.Values{
		"grant_type": {"authorization_code"},
		"client_id":  {"demo-bff"},
	}, testNow)
	if resp.StatusCode != 400 || !strings.Contains(resp.Body, "unsupported_grant_type") {
		t.Fatalf("status = %d body = %s, want 400 unsupported_grant_type", resp.StatusCode, resp.Body)
	}
}

func TestHandleIntrospectionInvalidTokenIsInactiveNotError(t *testing.T) {
	resp := handleIntrospection(context.Background(), testConfig(), url.Values{"token": {"junk"}}, testNow)
	if resp.StatusCode != 200 || !strings.Contains(resp.Body, `"active":false`) {
		t.Fatalf("status = %d body = %s, want 200 active:false", resp.StatusCode, resp.Body)
	}
}

func extractJSONField(t *testing.T, body, field string) string {
	t.Helper()
	marker := `"` + field + `":"`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("field %s not in %s", field, body)
	}
	rest := body[i+len(marker):]
	return rest[:strings.IndexByte(rest, '"')]
}
