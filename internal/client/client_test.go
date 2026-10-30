// Copyright 2026 joelcodess. Licensed under Apache-2.0. See LICENSE.

package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joelcodess/addigy-cli/internal/config"
)

func TestIsMutatingRequest(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{"GET", "/devices", false},
		{"GET", "/devices/query", false},
		{"POST", "/devices", true},
		{"POST", "/assets/default/alerts/query", false},  // /query POSTs are reads in v2
		{"POST", "/assets/default/alerts/query/", false}, // trailing slash tolerated
		{"PUT", "/facts/custom", true},
		{"PATCH", "/o/x/policies", true},
		{"DELETE", "/o/x/policies", true},
		{"DELETE", "/something/query", false},
		{"HEAD", "/devices", false},
	}
	for _, c := range cases {
		if got := isMutatingRequest(c.method, c.path); got != c.want {
			t.Errorf("isMutatingRequest(%q, %q) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

// newTestClient points a Client at a test server with no auth and rate limiting
// disabled, in non-interactive mode (NoInput) so the guardrail's refuse branch
// is deterministic.
func newTestClient(baseURL string) *Client {
	cfg := &config.Config{BaseURL: baseURL, BasePath: ""}
	c := New(cfg, 5*time.Second, 0)
	c.NoInput = true
	c.NoCache = true
	return c
}

func TestDo_RefusesMutationWithoutConfirmation(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL) // NoInput=true, AssumeYes=false

	_, _, err := c.Post("/self-service-configurations", map[string]any{"name": "x"})
	if err == nil {
		t.Fatal("expected refusal error for a mutation without --yes in non-interactive mode")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("error = %q, want a 'refusing to send' message", err.Error())
	}
	if hit {
		t.Fatal("guardrail breached: the mutation reached the server")
	}
}

func TestDo_AllowsMutationWithAssumeYes(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.AssumeYes = true // --yes / --agent bypass

	_, _, err := c.Post("/self-service-configurations", map[string]any{"name": "x"})
	if err != nil {
		t.Fatalf("unexpected error with AssumeYes: %v", err)
	}
	if !hit {
		t.Fatal("AssumeYes should have allowed the mutation to reach the server")
	}
}

func TestDeleteWithParams_TransmitsQueryParams(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.AssumeYes = true // delete is a mutation; bypass the confirm guardrail

	_, _, err := c.DeleteWithParams("/static-fields", map[string]string{"id": "abc123"})
	if err != nil {
		t.Fatalf("DeleteWithParams error: %v", err)
	}
	if gotQuery != "id=abc123" {
		t.Errorf("server received query %q, want id=abc123 (the id must be transmitted, not dropped)", gotQuery)
	}
}

func TestDo_AllowsQueryPostAsRead(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL) // NoInput=true, AssumeYes=false

	// A POST to a /query endpoint is a read and must NOT be gated.
	_, _, err := c.Post("/devices/query", map[string]any{})
	if err != nil {
		t.Fatalf("/query POST should be treated as a read, got error: %v", err)
	}
	if !hit {
		t.Fatal("/query POST should have reached the server without confirmation")
	}
}

func TestPostQuery_RefusesNonQueryPath(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	c.AssumeYes = true // even an auto-confirmed client must not mutate via PostQuery
	if _, _, err := c.PostQuery("/devices", nil, map[string]any{}); err == nil {
		t.Fatal("expected PostQuery to refuse a non-/query path")
	}
	if hit {
		t.Fatal("PostQuery reached the server for a non-/query path")
	}
}

func TestPostQuery_SendsParamsAndBody(t *testing.T) {
	var gotQuery, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		b := new(strings.Builder)
		_, _ = io.Copy(b, r.Body)
		gotBody = b.String()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL) // NoInput=true: a mutation would be refused
	if _, _, err := c.PostQuery("/oa/policies/query", map[string]string{"multitenancy": "false"}, map[string]any{"page": 1}); err != nil {
		t.Fatalf("PostQuery: %v", err)
	}
	if gotQuery != "multitenancy=false" {
		t.Errorf("query = %q, want multitenancy=false", gotQuery)
	}
	if gotBody != `{"page":1}` {
		t.Errorf("body = %q", gotBody)
	}
}
