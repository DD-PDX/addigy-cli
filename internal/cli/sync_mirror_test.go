// Copyright 2026 joelcodess. Licensed under Apache-2.0. See LICENSE.

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joelcodess/addigy-cli/internal/client"
	"github.com/joelcodess/addigy-cli/internal/config"
	"github.com/joelcodess/addigy-cli/internal/store"
)

func newSyncTestClient(baseURL string) *client.Client {
	c := client.New(&config.Config{BaseURL: baseURL, BasePath: ""}, 5*time.Second, 0)
	c.NoInput = true
	c.NoCache = true
	return c
}

func newSyncTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func storedRow(t *testing.T, db *store.Store, resource, id string) map[string]any {
	t.Helper()
	raw, err := db.Get(resource, id)
	if err != nil || raw == nil {
		t.Fatalf("%s/%s not stored: %v", resource, id, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decoding %s/%s: %v", resource, id, err)
	}
	return m
}

// Every default resource must resolve to a path, and every POST must go to a
// /query search: sync is a read-only mirror and may never reach a mutation.
func TestSyncDefaults_ReadOnlyAndResolvable(t *testing.T) {
	for _, r := range defaultSyncResources() {
		p, err := syncResourcePath(r)
		if err != nil {
			t.Errorf("%s: %v", r, err)
			continue
		}
		if _, ok := syncQuerySpecs[r]; ok && !strings.HasSuffix(p, "/query") && p != "/devices" {
			t.Errorf("%s is synced by POST but its path %q is not a /query search or the device search", r, p)
		}
	}
	for r := range syncQuerySpecs {
		if _, err := syncResourcePath(r); err != nil {
			t.Errorf("query spec %s has no path: %v", r, err)
		}
	}
	for r, spec := range syncDependentSpecs {
		if _, err := syncResourcePath(r); err != nil {
			t.Errorf("dependent %s has no path: %v", r, err)
		}
		if _, err := syncResourcePath(spec.Parent); err != nil {
			t.Errorf("dependent %s has unknown parent %s", r, spec.Parent)
		}
	}
}

// The new resources need an id override in both maps; a miss in either
// silently drops every row at upsert.
func TestSyncMirror_IDOverrides(t *testing.T) {
	cases := map[string]map[string]any{
		"policies":                  {"policyId": "p1", "name": "Policy"},
		"smart-software":            {"instruction_id": "i1", "identifier": "x"},
		"policy-rules":              {"rule_id": "r1"},
		"system-update-settings":    {"policy_id": "p1"},
		"variables":                 {"key": "k1", "type": "string"},
		"maintenance":               {"_id": "m1", "name": "Maint"},
		"device-script-assignments": {"id": "s1:a1"},
	}
	for resource, obj := range cases {
		if got := extractID(resource, obj); got == "" {
			t.Errorf("extractID(%s) = empty", resource)
		}
	}
}

func TestOrderSyncResources(t *testing.T) {
	parents, flat, dependents := orderSyncResources([]string{"system-update-settings", "scripts", "policies", "facts"})
	if strings.Join(parents, ",") != "policies" {
		t.Errorf("parents = %v", parents)
	}
	if strings.Join(flat, ",") != "scripts,facts" {
		t.Errorf("flat = %v", flat)
	}
	if strings.Join(dependents, ",") != "system-update-settings" {
		t.Errorf("dependents = %v", dependents)
	}
	if !needsOrgID([]string{"scripts"}) || needsOrgID([]string{"facts"}) {
		t.Error("needsOrgID: scripts is org-scoped, facts is not")
	}
}

func TestRedactSyncObject(t *testing.T) {
	webhook := map[string]any{
		"id": "w1", "name": "Hook", "secret_token": "s3cret",
		"action":  map[string]any{"url": "https://hooks.example/abc"},
		"headers": map[string]any{"Authorization": "Bearer x"},
	}
	if !redactSyncObject("webhooks", webhook) {
		t.Fatal("webhook not redacted")
	}
	if webhook["secret_token"] != redactedValue || webhook["headers"] != redactedValue ||
		webhook["action"].(map[string]any)["url"] != redactedValue {
		t.Errorf("webhook secrets survived: %v", webhook)
	}
	if webhook["name"] != "Hook" {
		t.Errorf("non-secret field changed: %v", webhook["name"])
	}

	variable := map[string]any{"key": "slackToken", "type": "secret", "default_value": "xoxb-1"}
	redactSyncObject("variables", variable)
	if variable["default_value"] != redactedValue || variable["key"] != "slackToken" || variable["type"] != "secret" {
		t.Errorf("variable redaction wrong: %v", variable)
	}

	identity := map[string]any{"id": "i1", "addigy_sync": map[string]any{"services": map[string]any{
		"azure": map[string]any{"client_id": "cid", "client_secret": "cs"},
		"okta":  map[string]any{"api_token": "tok"},
	}}}
	redactSyncObject("identity-configurations", identity)
	svc := identity["addigy_sync"].(map[string]any)["services"].(map[string]any)
	if svc["azure"].(map[string]any)["client_secret"] != redactedValue || svc["okta"].(map[string]any)["api_token"] != redactedValue {
		t.Errorf("identity secrets survived: %v", svc)
	}
	if svc["azure"].(map[string]any)["client_id"] != "cid" {
		t.Error("client_id should not be redacted")
	}

	profile := map[string]any{"payload_group_id": "g1", "payloads": []any{
		map[string]any{"payload_type": "com.apple.security.scep", "challenge": "c", "token_id": "t1"},
		map[string]any{"payload_type": "com.apple.wifi.managed", "Password": "p", "PayloadUUID": "u"},
		map[string]any{"payload_type": "com.apple.security.pkcs12", "payload_content": "MIIb64"},
	}}
	redactSyncObject("mdm-configurations-profiles", profile)
	payloads := profile["payloads"].([]any)
	if payloads[0].(map[string]any)["challenge"] != redactedValue || payloads[0].(map[string]any)["token_id"] != "t1" {
		t.Errorf("scep payload: %v", payloads[0])
	}
	if payloads[1].(map[string]any)["Password"] != redactedValue || payloads[1].(map[string]any)["PayloadUUID"] != "u" {
		t.Errorf("wifi payload: %v", payloads[1])
	}
	if payloads[2].(map[string]any)["payload_content"] != redactedValue {
		t.Errorf("pkcs12 payload: %v", payloads[2])
	}

	policy := map[string]any{"policyId": "p1", "name": "token rotation"}
	if redactSyncObject("policies", policy) {
		t.Error("policies have no redaction rules and must be left alone")
	}
}

func TestPrepareSyncItems_DeviceScriptAssignmentCompositeID(t *testing.T) {
	items := prepareSyncItems("device-script-assignments", []json.RawMessage{
		json.RawMessage(`{"script_id":"s1","agent_id":"a1","script":{"id":""}}`),
		json.RawMessage(`{"script_id":"s1"}`),
	})
	var first, second map[string]any
	_ = json.Unmarshal(items[0], &first)
	_ = json.Unmarshal(items[1], &second)
	if first["id"] != "s1:a1" {
		t.Errorf("composite id = %v, want s1:a1", first["id"])
	}
	if _, ok := second["id"]; ok {
		t.Errorf("partial composite must not produce an id: %v", second)
	}
}

// fakeAddigy serves the request shapes sync uses and records every request.
type fakeAddigy struct {
	mu       sync.Mutex
	requests []string
}

func (f *fakeAddigy) record(r *http.Request, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+" "+body)
}

func (f *fakeAddigy) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.record(r, string(raw))
		w.Header().Set("Content-Type", "application/json")
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/oa/policies/query":
			_, _ = io.WriteString(w, `[{"orgid":"org-1","policyId":"p1","name":"One"},{"orgid":"org-1","policyId":"p2","name":"Two"}]`)
		case r.Method == http.MethodPost && r.URL.Path == "/o/org-1/scripts/query":
			if body["page"] == float64(1) {
				_, _ = io.WriteString(w, `{"items":[{"id":"s1"},{"id":"s2"}],"metadata":{"page":1,"page_count":2}}`)
			} else {
				_, _ = io.WriteString(w, `{"items":[{"id":"s3"}],"metadata":{"page":2,"page_count":2}}`)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/devices":
			// Synthetic devices only; real device rows never go in fixtures.
			if body["page"] == float64(1) {
				_, _ = io.WriteString(w, `{"items":[{"agentid":"agent-a","facts":{"device_name":{"value":"Test Mac A"},"policy_ids":{"value":["p1"]}}}],"metadata":{"page":1,"page_count":2}}`)
			} else {
				_, _ = io.WriteString(w, `{"items":[{"agentid":"agent-b","facts":{"device_name":{"value":"Test Mac B"}}}],"metadata":{"page":2,"page_count":2}}`)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/oa/webhooks/query":
			_, _ = io.WriteString(w, `[{"id":"w1","secret_token":"tok","action":{"url":"https://x"}}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/o/org-1/policies/rules":
			// Addigy 301s the slashless form; the client must follow.
			http.Redirect(w, r, "/o/org-1/policies/rules/", http.StatusMovedPermanently)
		case r.Method == http.MethodGet && r.URL.Path == "/o/org-1/policies/rules/":
			_, _ = io.WriteString(w, `[{"rule_id":"r1"}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/system-updates/settings":
			if r.URL.Query().Get("policy_id") == "p2" {
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
				return
			}
			_, _ = io.WriteString(w, `{"policy_id":"`+r.URL.Query().Get("policy_id")+`","macos_settings":{"enabled":true}}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected", http.StatusTeapot)
		}
	})
}

func TestSyncResource_MirrorResources(t *testing.T) {
	fake := &fakeAddigy{}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()
	c := newSyncTestClient(srv.URL)
	db := newSyncTestStore(t)
	t.Setenv("ADDIGY_ORG_ID", "")

	if res := syncResource(c, db, "policies", "", true, 100, false, nil, nil); res.Err != nil || res.Count != 2 {
		t.Fatalf("policies: count=%d err=%v warn=%v", res.Count, res.Err, res.Warn)
	}
	env := &syncEnv{OrgID: resolveSyncOrgID("", db)}
	if env.OrgID != "org-1" {
		t.Fatalf("org id from mirrored policies = %q, want org-1", env.OrgID)
	}

	if res := syncResource(c, db, "scripts", "", true, 100, false, nil, env); res.Err != nil || res.Count != 3 {
		t.Fatalf("scripts: count=%d err=%v warn=%v", res.Count, res.Err, res.Warn)
	}
	if res := syncResource(c, db, "policy-rules", "", true, 100, false, nil, env); res.Err != nil || res.Count != 1 {
		t.Fatalf("policy-rules: count=%d err=%v warn=%v", res.Count, res.Err, res.Warn)
	}
	if res := syncResource(c, db, "devices", "", true, 100, false, nil, env); res.Err != nil || res.Count != 2 {
		t.Fatalf("devices: count=%d err=%v warn=%v", res.Count, res.Err, res.Warn)
	}
	if res := syncResource(c, db, "webhooks", "", true, 100, false, nil, env); res.Err != nil || res.Count != 1 {
		t.Fatalf("webhooks: count=%d err=%v warn=%v", res.Count, res.Err, res.Warn)
	}
	if res := syncResource(c, db, "system-update-settings", "", true, 100, false, nil, env); res.Err != nil || res.Count != 1 {
		t.Fatalf("system-update-settings: count=%d err=%v warn=%v", res.Count, res.Err, res.Warn)
	}

	hook := storedRow(t, db, "webhooks", "w1")
	if hook["secret_token"] != redactedValue || hook["action"].(map[string]any)["url"] != redactedValue {
		t.Errorf("webhook stored unredacted: %v", hook)
	}
	settings := storedRow(t, db, "system-update-settings", "p1")
	if settings["policy_name"] != "One" {
		t.Errorf("settings row missing parent name: %v", settings)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	var sawScriptsPage2, sawMultitenancy bool
	for _, req := range fake.requests {
		method, _, _ := strings.Cut(req, " ")
		if method == http.MethodPost && !strings.Contains(req, "/query?") && !strings.HasPrefix(req, "POST /devices? ") {
			t.Errorf("non-query POST sent: %s", req)
		}
		if method != http.MethodPost && method != http.MethodGet {
			t.Errorf("non-read method sent: %s", req)
		}
		if strings.HasPrefix(req, "POST /o/org-1/scripts/query") && strings.Contains(req, `"page":2`) {
			sawScriptsPage2 = true
		}
		if strings.HasPrefix(req, "POST /oa/policies/query?multitenancy=false") && strings.Contains(req, `"sort_field":"name"`) {
			sawMultitenancy = true
		}
	}
	if !sawScriptsPage2 {
		t.Error("scripts page 2 was never requested")
	}
	if !sawMultitenancy {
		t.Error("policies query missing multitenancy=false or sort_field")
	}
}

func TestSyncResource_OrgScopedSkippedWithoutOrg(t *testing.T) {
	db := newSyncTestStore(t)
	res := syncResource(newSyncTestClient("http://127.0.0.1:1"), db, "scripts", "", true, 100, false, nil, &syncEnv{})
	if res.Warn == nil || res.Err != nil {
		t.Fatalf("want unfilled-path warning, got err=%v warn=%v", res.Err, res.Warn)
	}
}

func TestSyncDependentResource_NoParents(t *testing.T) {
	db := newSyncTestStore(t)
	res := syncResource(newSyncTestClient("http://127.0.0.1:1"), db, "system-update-settings", "", true, 100, false, nil, nil)
	if res.Warn == nil || !strings.Contains(res.Warn.Error(), "no policies") {
		t.Fatalf("want no-parents warning, got err=%v warn=%v", res.Err, res.Warn)
	}
}

// Script bodies (smart software, custom facts, maintenance) embed
// credentials; the mirror must scrub them the way the tracking exporter does.
func TestRedactSecretText(t *testing.T) {
	cases := []struct {
		name, in string
		gone     string // must not survive
		kept     string // must survive
	}{
		{"slack webhook", `curl -X POST https://hooks.slack.com/services/T000/B000/abcdefghijklmnop -d x`, "abcdefghijklmnop", "curl -X POST"},
		{"assignment", "#!/bin/bash\nAPI_TOKEN=\"a1b2c3d4e5f6g7h8\"\necho done", "a1b2c3d4e5f6g7h8", "API_TOKEN="},
		{"psk assignment", "wifi_psk='CorrectHorse99'", "CorrectHorse99", "wifi_psk="},
		{"cli flag", `installer --site-token=Zx81kLmn0pQ`, "Zx81kLmn0pQ", "--site-token="},
		{"plist", `<key>Password</key><string>hunter2hunter2</string>`, "hunter2hunter2", "<key>Password</key>"},
		{"bearer", `-H "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"`, "abcdefghijklmnopqrstuvwxyz123456", "Authorization"},
		{"shell reference kept", `TOKEN=$SENTINEL_TOKEN`, "", "$SENTINEL_TOKEN"},
		{"safe key kept", `password_length=12345678`, "", "12345678"},
		{"uuid kept", `site_key=3f2504e0-4f89-11d3-9a0c-0305e82c3301`, "", "3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
	}
	for _, tc := range cases {
		got, _ := redactSecretText(tc.in)
		if tc.gone != "" && strings.Contains(got, tc.gone) {
			t.Errorf("%s: secret survived: %q", tc.name, got)
		}
		if !strings.Contains(got, tc.kept) {
			t.Errorf("%s: lost %q: %q", tc.name, tc.kept, got)
		}
	}
}

func TestPrepareSyncItem_ScrubsScriptBodies(t *testing.T) {
	item := prepareSyncItem("smart-software", json.RawMessage(
		`{"instruction_id":"i1","installation_script":"SITE_TOKEN=\"Q9w8e7r6t5y4u3i2\"\n/usr/sbin/installer -pkg x.pkg","api_token":"tok123456789"}`))
	s := string(item)
	if strings.Contains(s, "Q9w8e7r6t5y4u3i2") || strings.Contains(s, "tok123456789") {
		t.Errorf("secret survived prepare: %s", s)
	}
	if !strings.Contains(s, "/usr/sbin/installer -pkg x.pkg") {
		t.Errorf("script body damaged: %s", s)
	}
	rule := prepareSyncItem("oa-compliance-rules-pre-built", json.RawMessage(`{"id":"r","value":"password=abcdefgh1234"}`))
	if string(rule) != `{"id":"r","value":"password=abcdefgh1234"}` {
		t.Errorf("public catalog rows must pass through untouched: %s", rule)
	}
}
