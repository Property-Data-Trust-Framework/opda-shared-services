package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

func main() {
	l := logger()
	slog.SetDefault(l)
	ctx := context.Background()

	_, legacyMode := os.LookupEnv("PROXY_HOST_TARGET")
	_, routingMode := os.LookupEnv("SSM_ROUTES_PATH")

	if !legacyMode && !routingMode {
		msg := "must set PROXY_HOST_TARGET (legacy single-target) or SSM_ROUTES_PATH (path routing)"
		l.ErrorContext(ctx, msg)
		panic(msg)
	}

	for _, v := range []string{
		"SSM_TRANSPORT_KEY_NAME",
		"SSM_TRANSPORT_CERTIFICATE_NAME",
		"SSM_CA_TRUSTED_LIST_NAME",
	} {
		if _, found := os.LookupEnv(v); !found {
			msg := fmt.Sprintf("environment variable %s not set", v)
			l.ErrorContext(ctx, msg)
			panic(msg)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/health", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if legacyMode {
		slog.InfoContext(ctx, "proxy started", slog.String("mode", "legacy"))
		mux.Handle("/", reverseProxy())
	} else {
		slog.InfoContext(ctx, "proxy started", slog.String("mode", "routing"))
		rt, err := newRouteTable(ctx, os.Getenv("SSM_ROUTES_PATH"))
		if err != nil {
			slog.ErrorContext(ctx, "failed to load initial routes", slog.String("err", err.Error()))
			os.Exit(1)
		}
		go startRefreshLoop(ctx, rt, os.Getenv("SSM_ROUTES_PATH"))
		mux.Handle("/", rt.handler())
	}

	tlsConfig := tlsConfiguration()
	server := http.Server{
		Handler:           mux,
		ErrorLog:          slog.NewLogLogger(l.Handler(), slog.LevelError),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 30 * time.Second,
	}

	lnConfig := net.ListenConfig{}
	ln, err := lnConfig.Listen(ctx, "tcp", ":443")
	if err != nil {
		os.Exit(1)
	}
	slog.Info("Listening on port 443")
	slog.Error("server error", slog.String("err", server.Serve(tls.NewListener(ln, tlsConfig)).Error()))
}

// ── Legacy single-target mode (backward compat) ───────────────────────────────

func reverseProxy() http.Handler {
	target := os.Getenv("PROXY_HOST_TARGET")
	apiHost, err := parseProxyTarget(target)
	if err != nil {
		slog.Error("invalid proxy target", slog.String("err", err.Error()))
		os.Exit(1)
	}
	slog.Info("parsed proxy target")
	apiProxy := httputil.NewSingleHostReverseProxy(apiHost)
	origDirector := apiProxy.Director

	apiProxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = apiHost.Host
		setCustomHeaders(req, apiHost)
	}
	apiProxyHandler := loggingMiddleware(apiProxy)
	apiProxyHandler = enforceAccessTokenMiddleware(apiProxyHandler)

	return apiProxyHandler
}

// ── Path-routing mode ─────────────────────────────────────────────────────────

type routeEntry struct {
	prefix  string
	target  *url.URL
	handler http.Handler
}

type routeTable struct {
	mu     sync.RWMutex
	routes []routeEntry
}

func newRouteTable(ctx context.Context, ssmPath string) (*routeTable, error) {
	rt := &routeTable{}
	if err := rt.refresh(ctx, ssmPath); err != nil {
		return nil, err
	}
	return rt, nil
}

func (rt *routeTable) refresh(ctx context.Context, ssmPath string) error {
	entries, err := loadRoutesFromSSM(ctx, ssmPath)
	if err != nil {
		return err
	}
	// Longest prefix first so match() returns the most specific route.
	sort.Slice(entries, func(i, j int) bool {
		return len(entries[i].prefix) > len(entries[j].prefix)
	})
	rt.mu.Lock()
	rt.routes = entries
	rt.mu.Unlock()
	slog.InfoContext(ctx, "routes loaded", slog.Int("count", len(entries)))
	return nil
}

func (rt *routeTable) handler() http.Handler {
	return enforceAccessTokenMiddleware(loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt.mu.RLock()
		var h http.Handler
		for _, e := range rt.routes {
			if strings.HasPrefix(r.URL.Path, e.prefix) {
				h = e.handler
				break
			}
		}
		rt.mu.RUnlock()

		if h == nil {
			slog.Error("no route for path", slog.String("path", r.URL.Path))
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		h.ServeHTTP(w, r)
	})))
}

func startRefreshLoop(ctx context.Context, rt *routeTable, ssmPath string) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := rt.refresh(ctx, ssmPath); err != nil {
				slog.ErrorContext(ctx, "route refresh failed", slog.String("err", err.Error()))
			}
		case <-ctx.Done():
			return
		}
	}
}

func loadRoutesFromSSM(ctx context.Context, ssmPath string) ([]routeEntry, error) {
	local := strings.ToLower(os.Getenv("AWS_LOCAL")) == "true"
	region := os.Getenv("REGION")

	awsCfg, _ := config.LoadDefaultConfig(ctx, config.WithRegion(region))

	var client *ssm.Client
	if local {
		client = ssm.NewFromConfig(awsCfg, func(o *ssm.Options) {
			o.BaseEndpoint = aws.String("http://localstack.local:4566")
			o.Credentials = credentials.NewStaticCredentialsProvider("test", "test", "")
		})
	} else {
		client = ssm.NewFromConfig(awsCfg)
	}

	var entries []routeEntry
	var nextToken *string
	for {
		out, err := client.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
			Path:           aws.String(ssmPath),
			Recursive:      aws.Bool(false),
			WithDecryption: aws.Bool(false),
			NextToken:      nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("GetParametersByPath %s: %w", ssmPath, err)
		}

		for _, p := range out.Parameters {
			if p.Value == nil {
				continue
			}
			var v struct {
				Prefix string `json:"prefix"`
				URL    string `json:"url"`
			}
			if err := json.Unmarshal([]byte(*p.Value), &v); err != nil {
				slog.Warn("skipping malformed route param",
					slog.String("name", aws.ToString(p.Name)),
					slog.String("err", err.Error()))
				continue
			}
			target, err := parseProxyTarget(v.URL)
			if err != nil {
				slog.Warn("skipping route with invalid URL",
					slog.String("name", aws.ToString(p.Name)),
					slog.String("err", err.Error()))
				continue
			}
			entries = append(entries, newRouteEntry(v.Prefix, target))
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return entries, nil
}

func newRouteEntry(prefix string, target *url.URL) routeEntry {
	p := httputil.NewSingleHostReverseProxy(target)
	origDirector := p.Director
	p.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = target.Host
		setCustomHeaders(req, target)
	}
	return routeEntry{prefix: prefix, target: target, handler: p}
}

// ── TLS ───────────────────────────────────────────────────────────────────────

//nolint:gosec
func tlsConfiguration() *tls.Config {
	ssmCertName := os.Getenv("SSM_TRANSPORT_CERTIFICATE_NAME")
	ssmKeyName := os.Getenv("SSM_TRANSPORT_KEY_NAME")
	ssmCAName := os.Getenv("SSM_CA_TRUSTED_LIST_NAME")

	certPEM, keyPEM, caPEM, err := loadTlsFromSSM(context.Background(), ssmCertName, ssmKeyName, ssmCAName)
	if err != nil {
		log.Fatalf("failed to load TLS materials from SSM: %v", err)
	}

	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caPEM); !ok {
		log.Fatalf("failed to append CA certificates from SSM parameter %q", ssmCAName)
	}

	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("failed to parse server certificate/key from SSM: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
}

func loadTlsFromSSM(ctx context.Context, certName, keyName, caName string) (certPEM, keyPEM, caPEM []byte, err error) {
	local := strings.ToLower(os.Getenv("AWS_LOCAL")) == "true"
	region := os.Getenv("REGION")

	awsCfg, _ := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)

	var client *ssm.Client
	if local {
		client = ssm.NewFromConfig(awsCfg, func(o *ssm.Options) {
			o.BaseEndpoint = aws.String("http://localstack.local:4566")
			o.Credentials = credentials.NewStaticCredentialsProvider("test", "test", "")
		})
	} else {
		client = ssm.NewFromConfig(awsCfg)
	}

	get := func(name string, decrypt bool) ([]byte, error) {
		slog.Info("loading cert from SSM", slog.String("name", name))
		out, e := client.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           aws.String(name),
			WithDecryption: aws.Bool(decrypt),
		})
		if e != nil {
			return nil, e
		}
		if out.Parameter == nil || out.Parameter.Value == nil {
			return nil, fmt.Errorf("parameter %s is empty", name)
		}
		return []byte(*out.Parameter.Value), nil
	}

	certPEM, err = get(certName, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get cert: %w", err)
	}
	keyPEM, err = get(keyName, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get key: %w", err)
	}
	caPEM, err = get(caName, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get ca: %w", err)
	}

	return certPEM, keyPEM, caPEM, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func parseProxyTarget(target string) (*url.URL, error) {
	apiHost, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if apiHost.Scheme != "http" && apiHost.Scheme != "https" {
		return nil, fmt.Errorf("unsupported proxy target scheme")
	}
	if apiHost.Host == "" {
		return nil, fmt.Errorf("proxy target host is required")
	}
	if apiHost.User != nil {
		return nil, fmt.Errorf("proxy target must not contain user info")
	}
	return apiHost, nil
}

func loggingMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		h.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}

		attrs := []slog.Attr{
			slog.String("remoteIP", r.RemoteAddr),
			slog.String("host", r.Host),
			slog.String("request", r.RequestURI),
			slog.String("query", r.URL.RawQuery),
			slog.String("method", r.Method),
			slog.String("status", fmt.Sprintf("%d", rec.status)),
			slog.String("userAgent", r.UserAgent()),
			slog.String("referer", r.Referer()),
		}
		slog.LogAttrs(r.Context(), slog.LevelInfo, "access log", attrs...)
	})
}

func setCustomHeaders(req *http.Request, target *url.URL) {
	slog.Info("request before transformation",
		slog.String("method", req.Method),
		slog.String("url", req.URL.String()),
		slog.String("scheme", req.URL.Scheme),
		slog.String("host", req.Host),
		slog.String("path", req.URL.Path),
		slog.Any("query", req.URL.Query()),
		slog.Any("headers", req.Header),
	)

	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Host", req.Host)
	req.Header.Set("X-Real-IP", getRemoteIP(req))
	req.Header.Set("X-Forwarded-For", getForwardedFor(req))

	if len(req.TLS.PeerCertificates) > 0 {
		clientCert := req.TLS.PeerCertificates[0]
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: clientCert.Raw,
		})
		certPEMString := strings.ReplaceAll(string(certPEM), "\n", " ")
		req.Header.Set("TLS-Certificate", certPEMString)
		req.Header.Set("X-Certificate-DN", clientCert.Subject.String())
		req.Header.Set("X-Certificate-Verify", "SUCCESS")
	}

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host

	if target.RawQuery == "" || req.URL.RawQuery == "" {
		req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
	} else {
		req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
	}
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "")
	}
	slog.Info("request after transformation",
		slog.String("method", req.Method),
		slog.String("url", req.URL.String()),
		slog.String("scheme", req.URL.Scheme),
		slog.String("host", req.Host),
		slog.String("path", req.URL.Path),
		slog.Any("query", req.URL.Query()),
		slog.Any("headers", req.Header),
	)
}

func getRemoteIP(req *http.Request) string {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return ""
	}
	return ip
}

func getForwardedFor(req *http.Request) string {
	forwardedFor := req.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		return forwardedFor + ", " + getRemoteIP(req)
	}
	return getRemoteIP(req)
}

// tokenlessPathPrefixes are exempt from the bearer-presence check: the auth
// stub's endpoints (/auth/token, /auth/token/introspection) are tokenless by
// definition — they are where tokens come from (ADR-0012). Override the
// default with a comma-separated TOKENLESS_PATH_PREFIXES env var.
var tokenlessPathPrefixes = func() []string {
	v := os.Getenv("TOKENLESS_PATH_PREFIXES")
	if v == "" {
		v = "/auth/"
	}
	return strings.Split(v, ",")
}()

func enforceAccessTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range tokenlessPathPrefixes {
			if p != "" && strings.HasPrefix(r.URL.Path, p) {
				next.ServeHTTP(w, r)
				return
			}
		}
		accessToken := getAccessToken(r)
		if accessToken == "" {
			slog.Error("No Authorization header, returning 401")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getAccessToken(req *http.Request) string {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		authHeader = req.Header.Get("authorization")
	}
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

func logger() *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	handler := slog.NewJSONHandler(os.Stdout, opts)
	return slog.New(handler)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}
