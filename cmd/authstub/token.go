package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Stateless opaque token: base64url(client_id|scope|exp) + "." + base64url(HMAC-SHA256(payload)).
// No storage, no expiry housekeeping — introspection recomputes the MAC and checks exp.

var (
	errBadToken = errors.New("malformed token")
	errBadMAC   = errors.New("signature mismatch")
	errExpired  = errors.New("token expired")
)

type tokenClaims struct {
	ClientID string
	Scope    string
	Exp      int64
}

func mintToken(key []byte, clientID, scope string, ttl time.Duration, now time.Time) string {
	exp := now.Add(ttl).Unix()
	payload := fmt.Sprintf("%s|%s|%d", clientID, scope, exp)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) +
		"." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyToken(key []byte, token string, now time.Time) (tokenClaims, error) {
	dot := strings.LastIndexByte(token, '.')
	if dot < 0 {
		return tokenClaims{}, errBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		return tokenClaims{}, errBadToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(token[dot+1:])
	if err != nil {
		return tokenClaims{}, errBadToken
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return tokenClaims{}, errBadMAC
	}

	// client_id|scope|exp — scope itself may contain spaces but never pipes.
	parts := strings.Split(string(payload), "|")
	if len(parts) != 3 {
		return tokenClaims{}, errBadToken
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return tokenClaims{}, errBadToken
	}
	if now.Unix() >= exp {
		return tokenClaims{}, errExpired
	}
	return tokenClaims{ClientID: parts[0], Scope: parts[1], Exp: exp}, nil
}

// resolveScope validates a requested scope against the client's registered scopes.
// An empty request grants everything registered.
func resolveScope(registered []string, requested string) (string, error) {
	if strings.TrimSpace(requested) == "" {
		return strings.Join(registered, " "), nil
	}
	allowed := make(map[string]bool, len(registered))
	for _, s := range registered {
		allowed[s] = true
	}
	fields := strings.Fields(requested)
	for _, s := range fields {
		if !allowed[s] {
			return "", fmt.Errorf("scope %q not registered for client", s)
		}
	}
	return strings.Join(fields, " "), nil
}
