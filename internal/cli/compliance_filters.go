// Hand-authored for the DD-PDX fork. Not generated.
//
// Evaluation of Addigy compliance-rule filter_sets against mirrored device
// facts. A rule's filter_sets is a list of sets; the rule passes when every
// filter in at least one set matches (OR of ANDs), the same shape Addigy uses
// for policy assignment rule filters.

package cli

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

// parseFilterSets decodes a filter_sets value; anything malformed yields nil
// so the rule falls back to the plain field/op/value evaluation.
func parseFilterSets(v any) [][]map[string]any {
	sets, ok := v.([]any)
	if !ok {
		return nil
	}
	var out [][]map[string]any
	for _, s := range sets {
		filters, ok := s.([]any)
		if !ok || len(filters) == 0 {
			continue
		}
		var set []map[string]any
		for _, f := range filters {
			if m, ok := f.(map[string]any); ok {
				set = append(set, m)
			}
		}
		if len(set) > 0 {
			out = append(out, set)
		}
	}
	return out
}

// filterSetsCollected reports whether the device collects every fact the
// rule's filters read. Benchmark facts are only gathered on devices whose
// policy carries the benchmark, so a fact that is absent altogether means
// "not deployed here", not "failed"; such rules are not evaluated.
func filterSetsCollected(facts map[string]any, sets [][]map[string]any) bool {
	for _, set := range sets {
		for _, f := range set {
			if field, _ := f["audit_field"].(string); field != "" {
				if _, ok := facts[field]; !ok {
					return false
				}
			}
		}
	}
	return true
}

// evaluateFilterSets reports whether any set fully matches. On failure the
// reason names the first unmet filter of the first set.
func evaluateFilterSets(facts map[string]any, sets [][]map[string]any) (bool, string) {
	firstReason := ""
	for _, set := range sets {
		passed := true
		for _, f := range set {
			ok, reason := evaluateFilter(facts, f)
			if !ok {
				passed = false
				if firstReason == "" {
					firstReason = reason
				}
				break
			}
		}
		if passed {
			return true, ""
		}
	}
	return false, firstReason
}

// evaluateFilter checks one {audit_field, type, operation, <type>_value}
// filter. A null (or, when called directly, missing) fact uses
// options.default_value when present.
func evaluateFilter(facts map[string]any, f map[string]any) (bool, string) {
	field, _ := f["audit_field"].(string)
	if field == "" {
		return true, ""
	}
	op := strings.ToLower(strings.TrimSpace(fmt.Sprint(f["operation"])))
	typ, _ := f["type"].(string)
	want := filterWantValue(f, typ)

	var got any
	if fact, ok := facts[field]; ok {
		if m, isMap := fact.(map[string]any); isMap {
			got = m["value"]
		} else {
			got = fact
		}
	}
	if got == nil {
		if opts, ok := f["options"].(map[string]any); ok {
			got = opts["default_value"]
		}
	}
	if got == nil {
		return false, fmt.Sprintf("fact %q missing", field)
	}

	ok, supported := compareFilter(got, want, op, typ)
	if !supported {
		return false, fmt.Sprintf("unsupported operation %q on %s", op, field)
	}
	if ok {
		return true, ""
	}
	return false, fmt.Sprintf("%s=%v, want %s %v", field, got, op, want)
}

func filterWantValue(f map[string]any, typ string) any {
	for _, k := range []string{typ + "_value", "boolean_value", "string_value", "number_value", "integer_value", "float_value", "list_value", "value"} {
		if v, ok := f[k]; ok {
			return v
		}
	}
	return nil
}

// compareFilter returns (matched, supported).
func compareFilter(got, want any, op, typ string) (bool, bool) {
	gs, ws := factString(got), factString(want)
	switch op {
	case "=", "==", "equals", "is":
		return strings.EqualFold(gs, ws), true
	case "!=", "not equals", "does not equal", "is not":
		return !strings.EqualFold(gs, ws), true
	case "contains":
		return listOrStringContains(got, ws), true
	case "does not contain", "not contains":
		return !listOrStringContains(got, ws), true
	case "starts with", "begins with":
		return strings.HasPrefix(strings.ToLower(gs), strings.ToLower(ws)), true
	case "ends with":
		return strings.HasSuffix(strings.ToLower(gs), strings.ToLower(ws)), true
	case ">", "<", ">=", "<=":
		gn, err1 := strconv.ParseFloat(gs, 64)
		wn, err2 := strconv.ParseFloat(ws, 64)
		if err1 != nil || err2 != nil {
			return false, true
		}
		switch op {
		case ">":
			return gn > wn, true
		case "<":
			return gn < wn, true
		case ">=":
			return gn >= wn, true
		default:
			return gn <= wn, true
		}
	}
	return false, false
}

func factString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return fmt.Sprint(v)
}

func listOrStringContains(got any, want string) bool {
	if arr, ok := got.([]any); ok {
		for _, x := range arr {
			if strings.EqualFold(factString(x), want) {
				return true
			}
		}
		return false
	}
	return strings.Contains(strings.ToLower(factString(got)), strings.ToLower(want))
}

// osRange is a benchmark's [Min, Max) macOS version window; an empty bound
// is open.
type osRange struct {
	Min, Max string
}

// loadBenchmarkRuleRanges maps each rule id referenced by a synced benchmark
// to the OS ranges of the benchmarks that reference it.
func loadBenchmarkRuleRanges(db interface {
	Query(string, ...any) (*sql.Rows, error)
}) (map[string][]osRange, error) {
	rows, err := db.Query(`SELECT j.value,
		COALESCE(json_extract(b.data, '$.minimum_os_version'), ''),
		COALESCE(json_extract(b.data, '$.maximum_os_version'), '')
		FROM resources b, json_each(json_extract(b.data, '$.compliance_rules_ids')) j
		WHERE b.resource_type = 'benchmarks'`)
	if err != nil {
		return map[string][]osRange{}, nil
	}
	defer rows.Close()
	out := map[string][]osRange{}
	for rows.Next() {
		var id string
		var r osRange
		if err := rows.Scan(&id, &r.Min, &r.Max); err != nil {
			return nil, err
		}
		out[id] = append(out[id], r)
	}
	return out, rows.Err()
}

// ruleAppliesToOS reports whether a device on osVersion falls inside any of
// the rule's benchmark OS ranges. Rules without ranges, and devices whose OS
// is unknown, are always evaluated.
func ruleAppliesToOS(r rule, osVersion string) bool {
	if len(r.OSRanges) == 0 || osVersion == "" {
		return true
	}
	for _, rg := range r.OSRanges {
		if (rg.Min == "" || compareVersions(osVersion, rg.Min) >= 0) && (rg.Max == "" || compareVersions(osVersion, rg.Max) < 0) {
			return true
		}
	}
	return false
}

// compareVersions compares dotted numeric versions ("15.7.1" vs "15.0").
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(strings.TrimSpace(as[i]))
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(strings.TrimSpace(bs[i]))
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
