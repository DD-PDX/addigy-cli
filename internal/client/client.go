// Copyright 2026 joelcodess. Licensed under Apache-2.0. See LICENSE.

package client

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/joelcodess/addigy-cli/internal/cliutil"
	"github.com/joelcodess/addigy-cli/internal/config"

	"github.com/mattn/go-isatty"
)

type Client struct {
	BaseURL string
	// BasePath sits between BaseURL and the request path; empty unless the
	// spec declares base_path.
	BasePath   string
	Config     *config.Config
	HTTPClient *http.Client
	DryRun     bool
	NoCache    bool
	// AssumeYes skips the live-mutation confirmation prompt (set by --yes/--agent).
	// NoInput disables interactive prompts (set by --no-input/--agent); a mutation
	// without AssumeYes in non-interactive mode is refused rather than sent.
	AssumeYes bool
	NoInput   bool
	cacheDir  string
	limiter   *cliutil.AdaptiveLimiter
}

// UserAgent is sent on every outbound request so each call is unambiguously
// attributable to this CLI. The cli package overwrites it at init with the
// build version and platform (see internal/cli). It is sent unconditionally —
// even when a caller supplies custom headers — so requests always identify as
// addigy-cli.
var UserAgent = "addigy-cli"

// APIError carries HTTP status information for structured exit codes.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s returned HTTP %d: %s", e.Method, e.Path, e.StatusCode, e.Body)
}

// isMutatingRequest reports whether a request changes server state. POST
// endpoints whose path ends in /query are reads in Addigy v2 and are exempt.
func isMutatingRequest(method, path string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return !strings.HasSuffix(strings.TrimRight(path, "/"), "/query")
	default:
		return false
	}
}

// stdinIsTTY reports whether stdin is an interactive terminal (so we can
// prompt) versus a pipe, file, /dev/null, or CI (where prompting would hang
// or read EOF). Uses a real isatty ioctl rather than a char-device check,
// because /dev/null is a character device but not a terminal.
func stdinIsTTY() bool {
	fd := os.Stdin.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// confirmMutation prompts on stderr and reads a y/N answer from stdin.
func confirmMutation(method, url string) bool {
	fmt.Fprintf(os.Stderr, "About to send a live %s to %s\nThis modifies production data. Continue? [y/N]: ", method, url)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

func newHTTPClient(timeout time.Duration, jar http.CookieJar) *http.Client {
	return &http.Client{Timeout: timeout, Jar: jar}
}

func New(cfg *config.Config, timeout time.Duration, rateLimit float64) *Client {
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, ".cache", "addigy-cli", "http")
	httpClient := newHTTPClient(timeout, nil)
	return &Client{
		BaseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		BasePath:   normalizeBasePath(cfg.BasePath),
		Config:     cfg,
		HTTPClient: httpClient,
		cacheDir:   cacheDir,
		limiter:    cliutil.NewAdaptiveLimiter(rateLimit),
	}
}

// RateLimit returns the current effective rate limit in req/s. Returns 0 if disabled.
func (c *Client) RateLimit() float64 {
	return c.limiter.Rate()
}

func (c *Client) Get(path string, params map[string]string) (json.RawMessage, error) {
	return c.GetWithHeaders(path, params, nil)
}

func (c *Client) GetWithHeaders(path string, params map[string]string, headers map[string]string) (json.RawMessage, error) {
	// Check cache for GET requests
	if !c.NoCache && !c.DryRun && c.cacheDir != "" {
		if cached, ok := c.readCache(path, params); ok {
			return cached, nil
		}
	}
	result, _, err := c.do("GET", path, params, nil, headers)
	if err == nil && !c.NoCache && !c.DryRun && c.cacheDir != "" {
		c.writeCache(path, params, result)
	}
	return result, err
}

func (c *Client) ProbeGet(path string) (int, error) {
	_, status, err := c.do("GET", path, nil, nil, nil)
	return status, err
}

func (c *Client) cacheKey(path string, params map[string]string) string {
	key := path
	key += "|base_url=" + c.BaseURL
	key += "|base_path=" + c.BasePath
	if c.Config != nil {
		key += "|auth_source=" + c.Config.AuthSource
		if authHeader := c.Config.AuthHeader(); authHeader != "" {
			authHash := sha256.Sum256([]byte(c.Config.AuthHeader()))
			key += "|auth=" + hex.EncodeToString(authHash[:8])
		}
		if c.Config.Path != "" {
			key += "|config_path=" + c.Config.Path
		}
	}
	paramKeys := make([]string, 0, len(params))
	for k := range params {
		paramKeys = append(paramKeys, k)
	}
	sort.Strings(paramKeys)
	for _, k := range paramKeys {
		key += k + "=" + params[k]
	}
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:8])
}

func (c *Client) readCache(path string, params map[string]string) (json.RawMessage, bool) {
	cacheFile := filepath.Join(c.cacheDir, c.cacheKey(path, params)+".json")
	info, err := os.Stat(cacheFile)
	if err != nil || time.Since(info.ModTime()) > 5*time.Minute {
		return nil, false
	}
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, false
	}
	return json.RawMessage(data), true
}

func (c *Client) writeCache(path string, params map[string]string, data json.RawMessage) {
	// 0o700/0o600: cached responses hold tenant data (devices, inventory,
	// compliance) — owner-readable only, matching the credential file.
	os.MkdirAll(c.cacheDir, 0o700)
	cacheFile := filepath.Join(c.cacheDir, c.cacheKey(path, params)+".json")
	os.WriteFile(cacheFile, []byte(data), 0o600)
}

// invalidateCache wholesale-removes the cache directory so the next read
// after a mutation cannot return a stale snapshot. Selective per-resource
// invalidation rejected: cache keys are opaque sha256 hashes.
func (c *Client) invalidateCache() {
	if c.cacheDir == "" {
		return
	}
	_ = os.RemoveAll(c.cacheDir)
}

func (c *Client) Post(path string, body any) (json.RawMessage, int, error) {
	return c.do("POST", path, nil, body, nil)
}

// readOnlySearchPaths are POST endpoints outside the /query convention that
// are nonetheless pure reads. Matched exactly (no prefix, no trailing-slash
// variant). POST /devices is Addigy's device search and the only bulk device
// listing in the v2 API.
var readOnlySearchPaths = map[string]bool{
	"/devices": true,
}

// isReadOnlyPost reports whether a POST to path is a read PostQuery may send:
// a /query search, or one of the exact readOnlySearchPaths.
func isReadOnlyPost(path string) bool {
	return !isMutatingRequest(http.MethodPost, path) || readOnlySearchPaths[path]
}

// PostQuery sends a read-only Addigy v2 search (POST to a path ending in
// /query, or an exact readOnlySearchPaths entry) with query-string params such
// as multitenancy=false. Any other path is refused before a request is built,
// so callers like sync can never reach a mutating endpoint through this
// method. Because the path is known to be a read, the mutation confirmation
// guard does not apply.
func (c *Client) PostQuery(path string, params map[string]string, body any) (json.RawMessage, int, error) {
	if !isReadOnlyPost(path) {
		return nil, 0, fmt.Errorf("refusing POST %s: PostQuery only sends read-only search requests", path)
	}
	return c.send("POST", path, params, body, nil, true)
}

func (c *Client) PostWithHeaders(path string, body any, headers map[string]string) (json.RawMessage, int, error) {
	return c.do("POST", path, nil, body, headers)
}

func (c *Client) Delete(path string) (json.RawMessage, int, error) {
	return c.do("DELETE", path, nil, nil, nil)
}

// DeleteWithParams issues a DELETE with query parameters. Most Addigy v2 delete
// endpoints identify the target via a query param (e.g. ?id=, ?key=) rather than
// a path segment, so the generated delete commands must pass their flags here.
func (c *Client) DeleteWithParams(path string, params map[string]string) (json.RawMessage, int, error) {
	return c.do("DELETE", path, params, nil, nil)
}

func (c *Client) DeleteWithHeaders(path string, headers map[string]string) (json.RawMessage, int, error) {
	return c.do("DELETE", path, nil, nil, headers)
}

func (c *Client) Put(path string, body any) (json.RawMessage, int, error) {
	return c.do("PUT", path, nil, body, nil)
}

func (c *Client) PutWithHeaders(path string, body any, headers map[string]string) (json.RawMessage, int, error) {
	return c.do("PUT", path, nil, body, headers)
}

func (c *Client) Patch(path string, body any) (json.RawMessage, int, error) {
	return c.do("PATCH", path, nil, body, nil)
}

func (c *Client) PatchWithHeaders(path string, body any, headers map[string]string) (json.RawMessage, int, error) {
	return c.do("PATCH", path, nil, body, headers)
}

// do executes an HTTP request. headerOverrides, when non-nil, override global
// RequiredHeaders for this specific request (used for per-endpoint API versioning).
func (c *Client) do(method, path string, params map[string]string, body any, headerOverrides map[string]string) (json.RawMessage, int, error) {
	return c.send(method, path, params, body, headerOverrides, false)
}

// send is do with readOnly set by callers that have already verified the
// request is a read (PostQuery); readOnly skips the mutation guard and cache
// invalidation.
func (c *Client) send(method, path string, params map[string]string, body any, headerOverrides map[string]string, readOnly bool) (json.RawMessage, int, error) {
	mutating := !readOnly && isMutatingRequest(method, path)
	targetURL := c.BaseURL + c.BasePath + path

	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshaling body: %w", err)
		}
		bodyBytes = b
	}

	// Resolve auth material before the dry-run branch so --dry-run can preview
	// exactly what would be sent. Uses only cached credentials; a token that
	// requires a network refresh will be re-fetched on the live request path,
	// not during dry-run.
	authHeader, err := c.authHeader()
	if err != nil {
		return nil, 0, err
	}

	// Build the request for dry-run display or actual execution
	if c.DryRun {
		return c.dryRun(method, targetURL, path, params, bodyBytes, headerOverrides, authHeader)
	}

	// Live-mutation guardrail: a write that reaches a real tenant must be
	// confirmed. POST .../query endpoints are reads in Addigy v2 and are
	// exempt. --yes/--agent bypass; in non-interactive mode without --yes we
	// REFUSE rather than send, so a bare or mistyped mutating command cannot
	// silently hit production.
	if mutating && !c.AssumeYes {
		if c.NoInput || !stdinIsTTY() {
			return nil, 0, fmt.Errorf("refusing to send live %s %s without confirmation: pass --yes to proceed (or --dry-run to preview the request)", method, path)
		}
		if !confirmMutation(method, targetURL) {
			return nil, 0, fmt.Errorf("%s %s aborted: not confirmed", method, path)
		}
	}

	const maxRetries = 3
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Proactive rate limiting — wait before sending
		c.limiter.Wait()
		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = strings.NewReader(string(bodyBytes))
		}

		req, err := http.NewRequest(method, targetURL, bodyReader)
		if err != nil {
			return nil, 0, fmt.Errorf("creating request: %w", err)
		}
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		if params != nil {
			q := req.URL.Query()
			for k, v := range params {
				if v != "" {
					q.Set(k, v)
				}
			}
			req.URL.RawQuery = q.Encode()
		}

		if authHeader != "" {
			req.Header.Set("x-api-key", authHeader)
		}
		if c.Config != nil {
			for k, v := range c.Config.Headers {
				req.Header.Set(k, v)
			}
		}
		// Per-endpoint header overrides (e.g., different API version per resource)
		for k, v := range headerOverrides {
			req.Header.Set(k, v)
		}
		// Set last and unconditionally so the CLI identity always wins over any
		// config header or per-endpoint override above: every request is
		// attributable to addigy-cli.
		req.Header.Set("User-Agent", UserAgent)
		// Go's net/http omits Accept by default; browsers, curl, and other
		// stdlibs always send it. Fingerprint-checking WAFs (Imperva, Akamai,
		// Cloudflare bot-mode, DataDome) flag the absence as a bot signal
		// and answer with empty-body 5xx, 403, or a challenge redirect
		// depending on vendor and rule tier. The value is application/json
		// rather than */* because strict-JSON APIs (Zendesk, Atlassian REST,
		// Salesforce) return 415 on anything that isn't literally
		// application/json; specs that need a different content type
		// (vendor mediatypes, XML, HTML) declare it via RequiredHeaders or
		// per-endpoint headerOverrides, both of which run before this
		// if-empty default.
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "application/json")
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("%s %s: %w", method, path, err)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, 0, fmt.Errorf("reading response: %w", err)
		}
		respBody = sanitizeJSONResponse(respBody)

		// Success
		if resp.StatusCode < 400 {
			c.limiter.OnSuccess()
			if mutating && !c.DryRun {
				c.invalidateCache()
			}
			return json.RawMessage(respBody), resp.StatusCode, nil
		}

		apiErr := &APIError{
			Method:     method,
			Path:       path,
			StatusCode: resp.StatusCode,
			// Redact credential-shaped strings at the source: APIError.Body is
			// printed on every error path (human + --agent JSON), so if the
			// upstream reflects the api key into its response it must not leak.
			Body: cliutil.SanitizeErrorBody(truncateBody(respBody)),
		}

		// Rate limited - adjust adaptive limiter and retry
		if resp.StatusCode == 429 && attempt < maxRetries {
			c.limiter.OnRateLimit()
			wait := cliutil.RetryAfter(resp)
			fmt.Fprintf(os.Stderr, "rate limited, waiting %s (attempt %d/%d, rate adjusted to %.1f req/s)\n", wait, attempt+1, maxRetries, c.limiter.Rate())
			time.Sleep(wait)
			lastErr = apiErr
			continue
		}

		// Server error - retry with backoff
		if resp.StatusCode >= 500 && attempt < maxRetries {
			wait := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			fmt.Fprintf(os.Stderr, "server error %d, retrying in %s (attempt %d/%d)\n", resp.StatusCode, wait, attempt+1, maxRetries)
			time.Sleep(wait)
			lastErr = apiErr
			continue
		}

		// Client error or retries exhausted - return the error
		return nil, resp.StatusCode, apiErr
	}

	return nil, 0, lastErr
}

// dryRun prints the outgoing request exactly as the live path would send it,
// using the auth material already resolved in `do()`. Never triggers a network
// call — the caller is responsible for passing cached auth material only.
func (c *Client) dryRun(method, targetURL, path string, params map[string]string, body []byte, headerOverrides map[string]string, authHeader string) (json.RawMessage, int, error) {
	fmt.Fprintf(os.Stderr, "%s %s\n", method, targetURL)
	queryPrinted := false
	if params != nil {
		keys := make([]string, 0, len(params))
		for k := range params {
			if params[k] != "" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			sep := "?"
			if queryPrinted {
				sep = "&"
			}
			fmt.Fprintf(os.Stderr, "  %s%s=%s\n", sep, k, params[k])
			queryPrinted = true
		}
	}
	_ = queryPrinted
	if body != nil {
		var pretty json.RawMessage
		if json.Unmarshal(body, &pretty) == nil {
			enc := json.NewEncoder(os.Stderr)
			enc.SetIndent("  ", "  ")
			fmt.Fprintf(os.Stderr, "  Body:\n")
			enc.Encode(pretty)
		}
	}
	if authHeader != "" {
		fmt.Fprintf(os.Stderr, "  %s: %s\n", "x-api-key", maskToken(authHeader))
	}
	fmt.Fprintf(os.Stderr, "  %s: %s\n", "User-Agent", UserAgent)
	fmt.Fprintf(os.Stderr, "\n(dry run - no request sent)\n")
	return json.RawMessage(`{"dry_run": true}`), 0, nil
}

func (c *Client) ConfiguredTimeout() time.Duration {
	if c.HTTPClient != nil && c.HTTPClient.Timeout > 0 {
		return c.HTTPClient.Timeout
	}
	return 30 * time.Second
}

func (c *Client) authHeader() (string, error) {
	if c.Config == nil {
		return "", nil
	}
	return c.Config.AuthHeader(), nil
}

// normalizeBasePath trims surrounding whitespace and trailing slashes, then
// guarantees a single leading slash so concatenation with c.BaseURL produces
// well-formed URLs whether the operator wrote "/api/v1", "api/v1/", or
// "/api/v1/". Empty input stays empty so an unset override doesn't inject a
// stray "/" into the request URL.
func normalizeBasePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// sanitizeJSONResponse strips known JSONP/XSSI prefixes and UTF-8 BOM from
// response bodies so that downstream JSON parsing succeeds. For clean JSON
// responses these checks are no-ops.
func sanitizeJSONResponse(body []byte) []byte {
	// UTF-8 BOM
	body = bytes.TrimPrefix(body, []byte("\xEF\xBB\xBF"))

	// JSONP/XSSI prefixes, ordered longest-first where prefixes overlap
	prefixes := [][]byte{
		[]byte(")]}'\n"),
		[]byte(")]}'"),
		[]byte("{}&&"),
		[]byte("for(;;);"),
		[]byte("while(1);"),
	}
	for _, p := range prefixes {
		if bytes.HasPrefix(body, p) {
			body = bytes.TrimPrefix(body, p)
			body = bytes.TrimLeft(body, " \t\r\n")
			break
		}
	}
	return body
}

// maskToken redacts all but the last 4 characters of a token for safe display.
func maskToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 4 {
		return "****"
	}
	return "****" + token[len(token)-4:]
}

func truncateBody(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
