// Copyright 2026 joelcodess. Licensed under Apache-2.0. See LICENSE.

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// Synthetic rules and facts only; no real device data in fixtures.
func TestEvaluateRule_FilterSets(t *testing.T) {
	var raw map[string]any
	_ = json.Unmarshal([]byte(`{"id":"r1","name":"FileVault on","filter_sets":[[
		{"audit_field":"filevault_enabled","type":"boolean","operation":"=","boolean_value":true,"options":{"default_value":false}}
	]]}`), &raw)
	r := rule{ID: "r1", FilterSets: parseFilterSets(raw["filter_sets"])}
	if len(r.FilterSets) != 1 {
		t.Fatalf("parsed %d sets", len(r.FilterSets))
	}

	on := map[string]any{"filevault_enabled": map[string]any{"value": true}}
	if ok, reason := evaluateRule(on, r); !ok {
		t.Errorf("enabled device failed: %s", reason)
	}
	off := map[string]any{"filevault_enabled": map[string]any{"value": false}}
	if ok, reason := evaluateRule(off, r); ok || !strings.Contains(reason, "filevault_enabled") {
		t.Errorf("disabled device: ok=%v reason=%q", ok, reason)
	}
	// Missing fact falls back to options.default_value (false here).
	if ok, _ := evaluateRule(map[string]any{}, r); ok {
		t.Error("missing fact should use default_value=false and fail")
	}
}

func TestEvaluateFilterSets_OrOfAnds(t *testing.T) {
	sets := parseFilterSets([]any{
		[]any{
			map[string]any{"audit_field": "os_version", "type": "number", "operation": ">=", "number_value": 15.0},
			map[string]any{"audit_field": "policy_ids", "type": "list", "operation": "contains", "list_value": "p1"},
		},
		[]any{
			map[string]any{"audit_field": "device_name", "type": "string", "operation": "starts with", "string_value": "LAB-"},
		},
	})
	cases := []struct {
		name  string
		facts map[string]any
		want  bool
	}{
		{"first set", map[string]any{"os_version": map[string]any{"value": "15.1"}, "policy_ids": map[string]any{"value": []any{"p1", "p2"}}}, true},
		{"second set", map[string]any{"device_name": map[string]any{"value": "lab-07"}}, true},
		{"neither", map[string]any{"os_version": map[string]any{"value": "14.6"}, "policy_ids": map[string]any{"value": []any{"p1"}}}, false},
	}
	for _, tc := range cases {
		if got, _ := evaluateFilterSets(tc.facts, sets); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	if ok, reason := evaluateFilter(map[string]any{"x": map[string]any{"value": 1.0}}, map[string]any{"audit_field": "x", "operation": "matches regex", "string_value": "1"}); ok || !strings.Contains(reason, "unsupported") {
		t.Errorf("unknown op: ok=%v reason=%q", ok, reason)
	}
}

func TestParseSyncedAt(t *testing.T) {
	for _, s := range []string{
		"2026-10-30 11:59:07.612875 -0700 PDT m=+0.983641960",
		"2026-10-30 11:59:07.612875 -0700 PDT",
		"2026-10-30T18:59:07Z",
	} {
		if parseSyncedAt(s).IsZero() {
			t.Errorf("parseSyncedAt(%q) = zero", s)
		}
	}
}

func TestRuleAppliesToOS(t *testing.T) {
	r := rule{OSRanges: []osRange{{Min: "15.0", Max: "16.0"}, {Min: "26.0", Max: ""}}}
	cases := map[string]bool{"15.7.1": true, "14.8": false, "16.0": false, "26.7.2": true, "": true}
	for v, want := range cases {
		if got := ruleAppliesToOS(r, v); got != want {
			t.Errorf("ruleAppliesToOS(%q) = %v, want %v", v, got, want)
		}
	}
	if !ruleAppliesToOS(rule{}, "10.15") {
		t.Error("a rule without ranges applies everywhere")
	}
}

// Only org rules and benchmark-referenced pre-built rules are evaluated.
func TestLoadComplianceRules_ScopedToBenchmarks(t *testing.T) {
	db := newSyncTestStore(t)
	mustUpsert := func(resource, id, data string) {
		t.Helper()
		if err := db.Upsert(resource, id, json.RawMessage(data)); err != nil {
			t.Fatal(err)
		}
	}
	mustUpsert("oa-compliance-rules-pre-built", "used", `{"id":"used","name":"Used","filter_sets":[[{"audit_field":"a","operation":"=","boolean_value":true}]]}`)
	mustUpsert("oa-compliance-rules-pre-built", "unused", `{"id":"unused","name":"Unused","filter_sets":[[{"audit_field":"b","operation":"=","boolean_value":true}]]}`)
	mustUpsert("compliance-rules", "custom", `{"id":"custom","name":"Custom","filter_sets":[[{"audit_field":"c","operation":"=","boolean_value":true}]]}`)
	mustUpsert("benchmarks", "b1", `{"id":"b1","minimum_os_version":"15.0","maximum_os_version":"16.0","compliance_rules_ids":["used"]}`)

	rules, err := loadComplianceRules(db, "", "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]rule{}
	for _, r := range rules {
		got[r.ID] = r
	}
	if _, ok := got["unused"]; ok || len(got) != 2 {
		t.Fatalf("rules = %v, want used + custom", got)
	}
	if rs := got["used"].OSRanges; len(rs) != 1 || rs[0].Min != "15.0" {
		t.Errorf("used OSRanges = %v", rs)
	}
}

func TestFilterSetsCollected(t *testing.T) {
	sets := parseFilterSets([]any{[]any{map[string]any{"audit_field": "cis_fact", "operation": "=", "integer_value": 1.0}}})
	if filterSetsCollected(map[string]any{"other": map[string]any{"value": 1.0}}, sets) {
		t.Error("absent fact must mean not collected")
	}
	if !filterSetsCollected(map[string]any{"cis_fact": map[string]any{"value": nil}}, sets) {
		t.Error("a present-but-null fact is collected (default_value applies)")
	}
}
