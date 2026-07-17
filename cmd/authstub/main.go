package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// authstub is a sandbox replacement for the Raidiam directory (ADR-0012):
// a /token endpoint minting stateless HMAC tokens for clients registered in
// one SSM JSON parameter, and an RFC 7662 /token/introspection endpoint the
// per-API authorizer can be pointed at via OAUTH_ISSUER. Exposed as a private
// API Gateway routed through the shared mTLS proxy under /auth (public Lambda
// Function URLs need an un-IaC-able extra grant on this account — see
// Key-Learnings). It never returns
// `cnf`, so the authorizer's certificate binding self-disables.
//
// Deliberately NOT validated (sandbox-grade, see README): client_assertion
// signatures. Knowing a registered client_id yields a token — equivalent
// exposure to BYPASS_AUTH demo mode, but with real scope enforcement and
// audit logging.

var l *slog.Logger

type clientEntry struct {
	Scopes []string `json:"scopes"`
}

type stubConfig struct {
	clients  map[string]clientEntry
	hmacKey  []byte
	tokenTTL time.Duration
}

var (
	cfg     stubConfig
	cfgOnce sync.Once
	cfgErr  error
)

func loadConfig(ctx context.Context) (stubConfig, error) {
	cfgOnce.Do(func() {
		clientsParam := os.Getenv("SSM_CLIENTS_PARAM")
		keyParam := os.Getenv("SSM_HMAC_KEY_PARAM")
		if clientsParam == "" || keyParam == "" {
			cfgErr = fmt.Errorf("SSM_CLIENTS_PARAM and SSM_HMAC_KEY_PARAM must be set")
			return
		}

		ttl := 3600
		if v := os.Getenv("TOKEN_TTL_SECONDS"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				cfgErr = fmt.Errorf("invalid TOKEN_TTL_SECONDS %q", v)
				return
			}
			ttl = n
		}

		awsCfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			cfgErr = fmt.Errorf("loading AWS config: %w", err)
			return
		}
		client := ssm.NewFromConfig(awsCfg)

		withDecryption := true
		clientsOut, err := client.GetParameter(ctx, &ssm.GetParameterInput{
			Name: &clientsParam, WithDecryption: &withDecryption,
		})
		if err != nil {
			cfgErr = fmt.Errorf("reading %s: %w", clientsParam, err)
			return
		}
		keyOut, err := client.GetParameter(ctx, &ssm.GetParameterInput{
			Name: &keyParam, WithDecryption: &withDecryption,
		})
		if err != nil {
			cfgErr = fmt.Errorf("reading %s: %w", keyParam, err)
			return
		}

		var clients map[string]clientEntry
		if err := json.Unmarshal([]byte(*clientsOut.Parameter.Value), &clients); err != nil {
			cfgErr = fmt.Errorf("parsing client registry: %w", err)
			return
		}

		cfg = stubConfig{
			clients:  clients,
			hmacKey:  []byte(*keyOut.Parameter.Value),
			tokenTTL: time.Duration(ttl) * time.Second,
		}
	})
	return cfg, cfgErr
}

func jsonResponse(status int, body any) events.APIGatewayProxyResponse {
	b, _ := json.Marshal(body)
	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Cache-Control": "no-store",
		},
		Body: string(b),
	}
}

func oauthError(status int, code, description string) events.APIGatewayProxyResponse {
	return jsonResponse(status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func parseForm(req events.APIGatewayProxyRequest) (url.Values, error) {
	body := req.Body
	if req.IsBase64Encoded {
		raw, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return nil, fmt.Errorf("decoding body: %w", err)
		}
		body = string(raw)
	}
	return url.ParseQuery(body)
}

func handleToken(ctx context.Context, c stubConfig, form url.Values, now time.Time) events.APIGatewayProxyResponse {
	if form.Get("grant_type") != "client_credentials" {
		return oauthError(400, "unsupported_grant_type", "only client_credentials is supported")
	}
	clientID := form.Get("client_id")
	entry, known := c.clients[clientID]
	if clientID == "" || !known {
		l.InfoContext(ctx, "token denied", slog.String("client_id", clientID), slog.String("reason", "unknown client"))
		return oauthError(401, "invalid_client", "unknown client_id")
	}

	scope, err := resolveScope(entry.Scopes, form.Get("scope"))
	if err != nil {
		l.InfoContext(ctx, "token denied", slog.String("client_id", clientID), slog.String("reason", err.Error()))
		return oauthError(400, "invalid_scope", err.Error())
	}

	token := mintToken(c.hmacKey, clientID, scope, c.tokenTTL, now)
	l.InfoContext(ctx, "token minted", slog.String("client_id", clientID), slog.String("scope", scope))
	return jsonResponse(200, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(c.tokenTTL.Seconds()),
		"scope":        scope,
	})
}

func handleIntrospection(ctx context.Context, c stubConfig, form url.Values, now time.Time) events.APIGatewayProxyResponse {
	claims, err := verifyToken(c.hmacKey, form.Get("token"), now)
	if err != nil {
		l.InfoContext(ctx, "introspection: inactive", slog.String("reason", err.Error()))
		// RFC 7662: invalid tokens are reported as inactive, not as errors.
		return jsonResponse(200, map[string]any{"active": false})
	}
	l.InfoContext(ctx, "introspection: active", slog.String("client_id", claims.ClientID))
	// No `cnf` on purpose — the authorizer only enforces certificate binding
	// when introspection returns one.
	return jsonResponse(200, map[string]any{
		"active":     true,
		"client_id":  claims.ClientID,
		"scope":      claims.Scope,
		"exp":        claims.Exp,
		"token_type": "Bearer",
	})
}

func handleRequest(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	c, err := loadConfig(ctx)
	if err != nil {
		l.ErrorContext(ctx, "config load failed", slog.String("error", err.Error()))
		return jsonResponse(500, map[string]string{"error": "server_error"}), nil
	}

	if req.HTTPMethod != "POST" {
		return jsonResponse(405, map[string]string{"error": "method_not_allowed"}), nil
	}

	form, err := parseForm(req)
	if err != nil {
		return oauthError(400, "invalid_request", "body must be application/x-www-form-urlencoded"), nil
	}

	// Exposed through the shared proxy under the /auth route prefix; the API
	// Gateway resources carry the full path, so strip the prefix here.
	switch strings.TrimPrefix(req.Path, "/auth") {
	case "/token":
		return handleToken(ctx, c, form, time.Now()), nil
	case "/token/introspection":
		return handleIntrospection(ctx, c, form, time.Now()), nil
	default:
		return jsonResponse(404, map[string]string{"error": "not_found"}), nil
	}
}

func main() {
	l = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	l.Info("authstub started")
	lambda.Start(handleRequest)
}
