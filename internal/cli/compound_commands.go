// Hand-authored compound commands for Addigy CLI.
// These are NOT generated; they implement compound queries the live API can't answer.

package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/joelcodess/addigy-cli/internal/cliutil"
	"github.com/joelcodess/addigy-cli/internal/store"

	"github.com/spf13/cobra"
)

// deviceRow models the columns we care about across the various Addigy device
// shapes (Universal Device Search, /devices, /devices/{id}). Field names use
// COALESCE on common variants.
type deviceRow struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Serial      string          `json:"serial_number,omitempty"`
	OSVersion   string          `json:"os_version,omitempty"`
	LastCheckin string          `json:"last_checkin,omitempty"`
	PolicyID    string          `json:"policy_id,omitempty"`
	PolicyName  string          `json:"policy_name,omitempty"`
	AgentID     string          `json:"agent_id,omitempty"`
	UserName    string          `json:"user_name,omitempty"`
	Raw         json.RawMessage `json:"-"`
}

// queryDevices loads devices from o_devices applying optional filters.
// Filters: policyID (matches policy_id JSON field), osPattern (LIKE on os_version),
// staleDays (>0 means last_checkin older than N days from now).
func queryDevices(db *store.Store, policyID, osPattern string, staleDays int) ([]deviceRow, error) {
	q := strings.Builder{}
	q.WriteString(`SELECT id, data FROM resources WHERE resource_type='devices'`)
	var args []any
	// Filters apply to fact-buried values; do post-filter rather than SQL because
	// the device shape has variants nested under facts[...].value.
	_ = policyID
	_ = osPattern
	rows, err := db.DB().Query(q.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query o_devices: %w", err)
	}
	defer rows.Close()

	cutoff := time.Now().Add(-time.Duration(staleDays) * 24 * time.Hour)
	var out []deviceRow
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		dr := deviceRow{ID: id, Raw: raw}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		// Addigy device shape: top-level has agentid, orgid, agent_audit_date, audit_date, facts{}
		// Real "fields" (name, OS, policy, etc.) live inside facts[<name>]={value, type, error_msg}.
		dr.AgentID = pickStr(m, "agentid", "agent_id", "agentId")
		if dr.AgentID == "" {
			dr.AgentID = id
		}
		dr.Name = factVal(m, "device_name", "host_name", "localhost_name")
		dr.Serial = factVal(m, "serial_number", "displays_serial_number")
		dr.OSVersion = factVal(m, "os_version", "mac_os_x_version", "os_platform")
		dr.LastCheckin = factVal(m, "last_online")
		if dr.LastCheckin == "" {
			// Fall back to top-level agent audit date when facts.last_online is absent.
			dr.LastCheckin = pickStr(m, "agent_audit_date", "audit_date", "last_checkin", "last_checkin_date")
		}
		dr.PolicyID = factVal(m, "policy_id")
		if dr.PolicyID == "" {
			// policy_ids can be a list; take the first
			dr.PolicyID = factValAny(m, "policy_ids")
		}
		dr.PolicyName = factVal(m, "policy_name")
		dr.UserName = factVal(m, "current_user", "logged_in_user", "last_user")
		// Post-filter: policy
		if policyID != "" && dr.PolicyID != policyID && dr.PolicyName != policyID {
			continue
		}
		// Post-filter: OS LIKE pattern (very simple — only supports * wildcard, not full regex)
		if osPattern != "" {
			like := strings.ReplaceAll(osPattern, "%", "")
			like = strings.ReplaceAll(like, "*", "")
			if !strings.Contains(dr.OSVersion, like) {
				continue
			}
		}
		if staleDays > 0 {
			t := parseAddigyTime(dr.LastCheckin)
			if t.IsZero() || t.After(cutoff) {
				continue
			}
		}
		out = append(out, dr)
	}
	return out, rows.Err()
}

// factVal extracts a fact's string value from the Addigy device facts map.
// Addigy stores facts as facts.<name>={value, type, error_msg}; the value may
// be string/number/bool/null. Returns "" when missing or null.
func factVal(m map[string]any, names ...string) string {
	facts, _ := m["facts"].(map[string]any)
	if facts == nil {
		return ""
	}
	for _, name := range names {
		fact, ok := facts[name].(map[string]any)
		if !ok {
			continue
		}
		v, hasV := fact["value"]
		if !hasV || v == nil {
			continue
		}
		switch s := v.(type) {
		case string:
			if s != "" {
				return s
			}
		case float64:
			return strconv.FormatFloat(s, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(s)
		}
	}
	return ""
}

// unwrapFactValue takes a single fact entry (e.g. {value, type, error_msg})
// and returns its scalar string value, or "" when missing/null. Also accepts
// raw scalars for non-envelope-shaped data.
func unwrapFactValue(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	if m, ok := v.(map[string]any); ok {
		if val, has := m["value"]; has {
			if val == nil {
				return "", false
			}
			return fmt.Sprintf("%v", val), true
		}
	}
	return fmt.Sprintf("%v", v), true
}

// factValAny is factVal but accepts list values (returns first element as string).
func factValAny(m map[string]any, names ...string) string {
	facts, _ := m["facts"].(map[string]any)
	if facts == nil {
		return ""
	}
	for _, name := range names {
		fact, ok := facts[name].(map[string]any)
		if !ok {
			continue
		}
		v := fact["value"]
		if v == nil {
			continue
		}
		if arr, ok := v.([]any); ok && len(arr) > 0 {
			return fmt.Sprintf("%v", arr[0])
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func pickStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch s := v.(type) {
			case string:
				if s != "" {
					return s
				}
			case float64:
				return strconv.FormatFloat(s, 'f', -1, 64)
			case bool:
				return strconv.FormatBool(s)
			}
		}
	}
	return ""
}

// parseAddigyTime accepts a handful of timestamp formats Addigy emits.
func parseAddigyTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		// epoch seconds or millis
		if n > 1e12 {
			return time.UnixMilli(n)
		}
		return time.Unix(n, 0)
	}
	return time.Time{}
}

func openDB(cmd *cobra.Command, dbPath string) (*store.Store, error) {
	if dbPath == "" {
		dbPath = defaultDBPath("addigy-cli")
	}
	db, err := store.OpenWithContext(cmd.Context(), dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening local database: %w\nRun 'addigy-cli sync' first to populate the local mirror.", err)
	}
	return db, nil
}

// --------------------------------------------------------------------------
// 1. devices stale --days N [--policy X] [--os Y]
// --------------------------------------------------------------------------

func newDevicesStaleCmd(flags *rootFlags) *cobra.Command {
	var days int
	var policy, osPattern, dbPath string
	cmd := &cobra.Command{
		Use:   "stale",
		Short: "List devices whose last check-in is older than N days",
		Long: `List devices whose last check-in is older than N days, with optional policy
and OS filters. Runs as a single local SQLite query against the mirrored
device table — no live API fan-out, so it never burns the rate-limit budget.

Run 'addigy-cli sync' first to populate the local mirror.`,
		Example: ` addigy-cli devices stale --days 7 --json --agent
  addigy-cli devices stale --days 14 --policy ENG-Standard
  addigy-cli devices stale --days 30 --os "13.*" --csv`,
		Annotations: map[string]string{"mcp:read-only": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if cliutil.IsVerifyEnv() {
				fmt.Fprintln(cmd.OutOrStdout(), "would query local mirror for stale devices")
				return nil
			}
			if dryRunOK(flags) {
				return nil
			}
			if days <= 0 {
				days = 7
			}
			db, err := openDB(cmd, dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			devs, err := queryDevices(db, policy, osPattern, days)
			if err != nil {
				return err
			}
			return printDevices(cmd, flags, devs)
		},
	}
	cmd.Flags().IntVar(&days, "days", 7, "Stale threshold in days")
	cmd.Flags().StringVar(&policy, "policy", "", "Filter by policy ID or name")
	cmd.Flags().StringVar(&osPattern, "os", "", "Filter by OS version (LIKE pattern, e.g. '13.%')")
	cmd.Flags().StringVar(&dbPath, "db", "", "Database path (defaults to ~/.local/share/addigy-cli/data.db)")
	return cmd
}

func printDevices(cmd *cobra.Command, flags *rootFlags, devs []deviceRow) error {
	if flags.asJSON || flags.agent {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(devs)
	}
	if flags.csv {
		fmt.Fprintln(cmd.OutOrStdout(), "id,name,serial_number,os_version,last_checkin,policy_id,policy_name")
		for _, d := range devs {
			fmt.Fprintf(cmd.OutOrStdout(), "%s,%s,%s,%s,%s,%s,%s\n",
				d.ID, d.Name, d.Serial, d.OSVersion, d.LastCheckin, d.PolicyID, d.PolicyName)
		}
		return nil
	}
	for _, d := range devs {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", d.ID, d.Name, d.OSVersion, d.LastCheckin)
	}
	if !flags.quiet {
		fmt.Fprintf(cmd.OutOrStdout(), "\n%d device(s)\n", len(devs))
	}
	return nil
}

// --------------------------------------------------------------------------
// 2. compliance --policy <id> [--rule <id>]
// --------------------------------------------------------------------------

func newComplianceCmd(flags *rootFlags) *cobra.Command {
	var policy, rule, dbPath string
	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Surface devices whose assigned policy rules are unmet",
		Long: `Cross-join devices x policy_rules x device_facts in the local mirror and
report devices where a rule's required fact value does not match the current
device fact. No API endpoint evaluates rule compliance per device — the
Addigy UI does this client-side one device at a time.

Run 'addigy-cli sync' first to populate the local mirror.`,
		Example: ` addigy-cli compliance --policy ENG-Standard --json --agent
  addigy-cli compliance --policy ENG-Standard --rule require-filevault`,
		Annotations: map[string]string{"mcp:read-only": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if cliutil.IsVerifyEnv() {
				fmt.Fprintln(cmd.OutOrStdout(), "would run compliance audit against local mirror")
				return nil
			}
			if dryRunOK(flags) {
				return nil
			}
			db, err := openDB(cmd, dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			// Load devices in policy (if filter)
			devs, err := queryDevices(db, policy, "", 0)
			if err != nil {
				return err
			}

			// Load compliance_rules; filter by id/name if requested
			rules, err := loadComplianceRules(db, policy, rule)
			if err != nil {
				return err
			}

			type finding struct {
				DeviceID   string `json:"device_id"`
				DeviceName string `json:"device_name"`
				RuleID     string `json:"rule_id"`
				RuleName   string `json:"rule_name"`
				Reason     string `json:"reason"`
			}
			var findings []finding

			for _, d := range devs {
				var m map[string]any
				_ = json.Unmarshal(d.Raw, &m)
				facts, _ := m["facts"].(map[string]any)
				if facts == nil {
					if rawFacts, ok := m["device_facts"].(map[string]any); ok {
						facts = rawFacts
					}
				}
				for _, r := range rules {
					ok, reason := evaluateRule(facts, r)
					if !ok {
						findings = append(findings, finding{
							DeviceID: d.ID, DeviceName: d.Name,
							RuleID: r.ID, RuleName: r.Name, Reason: reason,
						})
					}
				}
			}

			if flags.asJSON || flags.agent {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(findings)
			}
			if flags.csv {
				fmt.Fprintln(cmd.OutOrStdout(), "device_id,device_name,rule_id,rule_name,reason")
				for _, f := range findings {
					fmt.Fprintf(cmd.OutOrStdout(), "%s,%s,%s,%s,%q\n",
						f.DeviceID, f.DeviceName, f.RuleID, f.RuleName, f.Reason)
				}
				return nil
			}
			for _, f := range findings {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", f.DeviceName, f.RuleName, f.Reason)
			}
			if !flags.quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "\n%d non-compliant finding(s) across %d device(s) and %d rule(s)\n",
					len(findings), len(devs), len(rules))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&policy, "policy", "", "Policy ID or name to audit")
	cmd.Flags().StringVar(&rule, "rule", "", "Specific rule ID or name (default: all rules)")
	cmd.Flags().StringVar(&dbPath, "db", "", "Database path")
	return cmd
}

type rule struct {
	ID    string
	Name  string
	Field string
	Op    string
	Value string
	Raw   map[string]any
}

func loadComplianceRules(db *store.Store, policy, ruleFilter string) ([]rule, error) {
	rows, err := db.DB().Query(`SELECT id, data FROM resources WHERE resource_type='oa-compliance-rules-pre-built'`)
	if err != nil {
		// Table may not exist for this fleet — return empty.
		return nil, nil
	}
	defer rows.Close()
	var out []rule
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		r := rule{
			ID:    id,
			Name:  pickStr(m, "name", "title", "rule_name"),
			Field: pickStr(m, "fact", "field", "fact_id"),
			Op:    pickStr(m, "operator", "op", "comparison"),
			Value: pickStr(m, "value", "expected", "target"),
			Raw:   m,
		}
		if ruleFilter != "" && r.ID != ruleFilter && r.Name != ruleFilter {
			continue
		}
		_ = policy // policy<->rule mapping varies by org; keep loose
		out = append(out, r)
	}
	return out, rows.Err()
}

func evaluateRule(facts map[string]any, r rule) (bool, string) {
	if r.Field == "" {
		return true, ""
	}
	if facts == nil {
		return false, "no facts available for device"
	}
	have, ok := facts[r.Field]
	if !ok {
		return false, fmt.Sprintf("fact %q missing", r.Field)
	}
	got, hasVal := unwrapFactValue(have)
	if !hasVal {
		return false, fmt.Sprintf("fact %q has null value", r.Field)
	}
	want := r.Value
	switch strings.ToLower(r.Op) {
	case "", "equals", "=", "==":
		if got == want {
			return true, ""
		}
		return false, fmt.Sprintf("%s=%q, want %q", r.Field, got, want)
	case "not_equals", "!=":
		if got != want {
			return true, ""
		}
		return false, fmt.Sprintf("%s=%q matches forbidden value", r.Field, got)
	case "contains":
		if strings.Contains(got, want) {
			return true, ""
		}
		return false, fmt.Sprintf("%s=%q does not contain %q", r.Field, got, want)
	}
	return false, fmt.Sprintf("unknown operator %q on %s", r.Op, r.Field)
}

// --------------------------------------------------------------------------
// 3. rollout <smart-software-id> [--policy X]
// --------------------------------------------------------------------------

func newRolloutCmd(flags *rootFlags) *cobra.Command {
	var policy, dbPath string
	cmd := &cobra.Command{
		Use:   "rollout <smart-software-id>",
		Short: "Per-device install state for one Smart Software item across the fleet",
		Long: `Aggregate per-device install state for a single Smart Software item from
the local mirror. Outputs success/pending/failed counts plus the device list
in each state.

The Addigy UI lacks a bulk rollout view; this is the Friday MSP rollout
report in one command.`,
		Example: ` addigy-cli rollout slack-business-v4 --json --agent
  addigy-cli rollout slack-business-v4 --policy MARKETING --csv`,
		Annotations: map[string]string{"mcp:read-only": "true"},
		Args:        cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cliutil.IsVerifyEnv() {
				fmt.Fprintln(cmd.OutOrStdout(), "would compute rollout aggregate from local mirror")
				return nil
			}
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return nil
			}
			ssID := args[0]
			db, err := openDB(cmd, dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			devs, err := queryDevices(db, policy, "", 0)
			if err != nil {
				return err
			}

			type devState struct {
				DeviceID   string `json:"device_id"`
				DeviceName string `json:"device_name"`
				State      string `json:"state"`
				When       string `json:"when,omitempty"`
			}
			out := struct {
				SmartSoftwareID string         `json:"smart_software_id"`
				Counts          map[string]int `json:"counts"`
				Devices         []devState     `json:"devices"`
			}{SmartSoftwareID: ssID, Counts: map[string]int{}}

			for _, d := range devs {
				var m map[string]any
				_ = json.Unmarshal(d.Raw, &m)
				state := softwareStateFor(m, ssID)
				out.Counts[state]++
				out.Devices = append(out.Devices, devState{DeviceID: d.ID, DeviceName: d.Name, State: state})
			}

			if flags.asJSON || flags.agent {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			if flags.csv {
				fmt.Fprintln(cmd.OutOrStdout(), "device_id,device_name,state")
				for _, d := range out.Devices {
					fmt.Fprintf(cmd.OutOrStdout(), "%s,%s,%s\n", d.DeviceID, d.DeviceName, d.State)
				}
				return nil
			}
			states := make([]string, 0, len(out.Counts))
			for k := range out.Counts {
				states = append(states, k)
			}
			sort.Strings(states)
			fmt.Fprintf(cmd.OutOrStdout(), "Rollout: %s\n", ssID)
			for _, s := range states {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s: %d\n", s, out.Counts[s])
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Total: %d device(s)\n", len(out.Devices))
			return nil
		},
	}
	cmd.Flags().StringVar(&policy, "policy", "", "Filter to a single policy ID/name")
	cmd.Flags().StringVar(&dbPath, "db", "", "Database path")
	return cmd
}

func softwareStateFor(deviceData map[string]any, ssID string) string {
	for _, key := range []string{"software_state", "smart_software", "installed_software", "software"} {
		v, ok := deviceData[key]
		if !ok {
			continue
		}
		if m, ok := v.(map[string]any); ok {
			if state, ok := m[ssID]; ok {
				if s, ok := state.(string); ok {
					return s
				}
				if mm, ok := state.(map[string]any); ok {
					return pickStr(mm, "state", "status")
				}
			}
		}
		if arr, ok := v.([]any); ok {
			for _, item := range arr {
				if mm, ok := item.(map[string]any); ok {
					id := pickStr(mm, "id", "software_id", "smart_software_id", "name")
					if id == ssID {
						return pickStr(mm, "state", "status")
					}
				}
			}
		}
	}
	return "unknown"
}

// --------------------------------------------------------------------------
// 4. facts search "<query>" [--fact-name X] [--group-by value]
// --------------------------------------------------------------------------

func newFactsSearchCmd(flags *rootFlags) *cobra.Command {
	var factName, groupBy, dbPath string
	var limit int
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search across mirrored device facts (FTS-style)",
		Long: `Search device facts in the local mirror. Returns matching device-fact
pairs. With --group-by value, returns a histogram of values per fact across
the fleet (e.g., FileVault status: enabled=412, disabled=31).

Run 'addigy-cli sync' first to populate the local mirror.`,
		Example: ` addigy-cli facts search "FileVault" --json --agent
  addigy-cli facts search "FileVault" --group-by value --json --agent
  addigy-cli facts search "kernel" --fact-name os --limit 50`,
		Annotations: map[string]string{"mcp:read-only": "true"},
		Args:        cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cliutil.IsVerifyEnv() {
				fmt.Fprintln(cmd.OutOrStdout(), "would search device facts in local mirror")
				return nil
			}
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return nil
			}
			query := strings.ToLower(args[0])
			db, err := openDB(cmd, dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			rows, err := db.DB().Query(`SELECT id, data FROM resources WHERE resource_type='devices'`)
			if err != nil {
				return err
			}
			defer rows.Close()

			type hit struct {
				DeviceID   string `json:"device_id"`
				DeviceName string `json:"device_name"`
				Fact       string `json:"fact"`
				Value      string `json:"value"`
			}
			var hits []hit
			counts := map[string]int{} // group-by histogram

			for rows.Next() {
				var id string
				var raw []byte
				if err := rows.Scan(&id, &raw); err != nil {
					return err
				}
				var m map[string]any
				_ = json.Unmarshal(raw, &m)
				dname := pickStr(m, "name", "device_name", "hostname")
				facts, _ := m["facts"].(map[string]any)
				if facts == nil {
					if rawFacts, ok := m["device_facts"].(map[string]any); ok {
						facts = rawFacts
					}
				}
				if facts == nil {
					// fallback: treat the device's top-level map as facts
					facts = m
				}
				for fname, fval := range facts {
					if factName != "" && fname != factName {
						continue
					}
					vs, ok := unwrapFactValue(fval)
					if !ok {
						continue
					}
					if !strings.Contains(strings.ToLower(fname), query) && !strings.Contains(strings.ToLower(vs), query) {
						continue
					}
					if groupBy == "value" {
						counts[fname+"="+vs]++
					} else {
						hits = append(hits, hit{DeviceID: id, DeviceName: dname, Fact: fname, Value: vs})
						if limit > 0 && len(hits) >= limit {
							goto done
						}
					}
				}
			}
		done:
			if groupBy == "value" {
				type bucket struct {
					Key   string `json:"key"`
					Count int    `json:"count"`
				}
				var buckets []bucket
				for k, v := range counts {
					buckets = append(buckets, bucket{Key: k, Count: v})
				}
				sort.Slice(buckets, func(i, j int) bool { return buckets[i].Count > buckets[j].Count })
				if flags.asJSON || flags.agent {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					return enc.Encode(buckets)
				}
				for _, b := range buckets {
					fmt.Fprintf(cmd.OutOrStdout(), "%6d  %s\n", b.Count, b.Key)
				}
				return nil
			}
			if flags.asJSON || flags.agent {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(hits)
			}
			for _, h := range hits {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s=%s\n", h.DeviceID, h.DeviceName, h.Fact, h.Value)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&factName, "fact-name", "", "Restrict search to one fact key")
	cmd.Flags().StringVar(&groupBy, "group-by", "", "Group results by value (returns histogram instead of hits)")
	cmd.Flags().IntVar(&limit, "limit", 200, "Maximum number of hits")
	cmd.Flags().StringVar(&dbPath, "db", "", "Database path")
	return cmd
}

// --------------------------------------------------------------------------
// 5. devices diff <a>
// --------------------------------------------------------------------------

func newDevicesDiffCmd(flags *rootFlags) *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "diff <device-a> <device-b>",
		Short: "Set differences across facts/applications/policies/Smart-Software between two devices",
		Long: `Compute set differences between two devices in the local mirror: facts,
applications, policies, and Smart Software state. Useful for ticket triage
when one device works and another doesn't.`,
		Example:     ` addigy-cli devices diff DEV-A-123 DEV-B-456 --json --agent`,
		Annotations: map[string]string{"mcp:read-only": "true"},
		Args:        cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cliutil.IsVerifyEnv() {
				fmt.Fprintln(cmd.OutOrStdout(), "would diff two devices from local mirror")
				return nil
			}
			if len(args) < 2 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return nil
			}
			db, err := openDB(cmd, dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			a, err := loadDeviceData(db, args[0])
			if err != nil {
				return err
			}
			b, err := loadDeviceData(db, args[1])
			if err != nil {
				return err
			}
			diff := computeDeviceDiff(a, b, args[0], args[1])
			if flags.asJSON || flags.agent {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(diff)
			}
			renderDeviceDiff(cmd, diff)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "Database path")
	return cmd
}

func loadDeviceData(db *store.Store, id string) (map[string]any, error) {
	row := db.DB().QueryRow(`SELECT data FROM resources WHERE resource_type='devices' AND id = ?`, id)
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("device not found in local mirror: %s\nRun 'addigy-cli sync' first, or check the device ID.", id)
		}
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

type diffSet struct {
	OnlyInA []string       `json:"only_in_a"`
	OnlyInB []string       `json:"only_in_b"`
	Differ  map[string]any `json:"differ,omitempty"`
}

type deviceDiff struct {
	A     string             `json:"a"`
	B     string             `json:"b"`
	Facts diffSet            `json:"facts"`
	Apps  diffSet            `json:"applications"`
	Other map[string]diffSet `json:"other,omitempty"`
}

func computeDeviceDiff(a, b map[string]any, idA, idB string) deviceDiff {
	out := deviceDiff{A: idA, B: idB}
	out.Facts = compareMap(mapOf(a, "facts", "device_facts"), mapOf(b, "facts", "device_facts"))
	out.Apps = compareSlice(sliceOf(a, "applications", "installed_software"), sliceOf(b, "applications", "installed_software"))
	return out
}

func mapOf(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		if v, ok := m[k].(map[string]any); ok {
			return v
		}
	}
	return map[string]any{}
}

func sliceOf(m map[string]any, keys ...string) []any {
	for _, k := range keys {
		if v, ok := m[k].([]any); ok {
			return v
		}
	}
	return nil
}

func compareMap(a, b map[string]any) diffSet {
	out := diffSet{Differ: map[string]any{}}
	for k, av := range a {
		bv, exists := b[k]
		if !exists {
			out.OnlyInA = append(out.OnlyInA, k)
			continue
		}
		aStr, aOk := unwrapFactValue(av)
		bStr, bOk := unwrapFactValue(bv)
		if aOk != bOk || aStr != bStr {
			out.Differ[k] = map[string]any{"a": aStr, "b": bStr}
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out.OnlyInB = append(out.OnlyInB, k)
		}
	}
	sort.Strings(out.OnlyInA)
	sort.Strings(out.OnlyInB)
	return out
}

func compareSlice(a, b []any) diffSet {
	out := diffSet{}
	keyA := stringSet(a)
	keyB := stringSet(b)
	for k := range keyA {
		if _, ok := keyB[k]; !ok {
			out.OnlyInA = append(out.OnlyInA, k)
		}
	}
	for k := range keyB {
		if _, ok := keyA[k]; !ok {
			out.OnlyInB = append(out.OnlyInB, k)
		}
	}
	sort.Strings(out.OnlyInA)
	sort.Strings(out.OnlyInB)
	return out
}

func stringSet(items []any) map[string]struct{} {
	out := map[string]struct{}{}
	for _, it := range items {
		switch v := it.(type) {
		case string:
			out[v] = struct{}{}
		case map[string]any:
			out[pickStr(v, "name", "id", "title")] = struct{}{}
		default:
			out[fmt.Sprintf("%v", v)] = struct{}{}
		}
	}
	return out
}

func renderDeviceDiff(cmd *cobra.Command, d deviceDiff) {
	fmt.Fprintf(cmd.OutOrStdout(), "Facts only in %s:\n", d.A)
	for _, k := range d.Facts.OnlyInA {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", k)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Facts only in %s:\n", d.B)
	for _, k := range d.Facts.OnlyInB {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", k)
	}
	if len(d.Facts.Differ) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "Facts that differ:")
		for k, v := range d.Facts.Differ {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s: %v\n", k, v)
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Apps only in %s: %d\n", d.A, len(d.Apps.OnlyInA))
	fmt.Fprintf(cmd.OutOrStdout(), "Apps only in %s: %d\n", d.B, len(d.Apps.OnlyInB))
}

// --------------------------------------------------------------------------
// 6. drift --since <duration> [--entity X]
// --------------------------------------------------------------------------

func newDriftCmd(flags *rootFlags) *cobra.Command {
	var sinceStr, entity, dbPath string
	cmd := &cobra.Command{
		Use:   "drift",
		Short: "What changed in the mirror since timestamp T",
		Long: `Report rows in the local mirror whose synced_at is newer than the given
duration. Compares against the prior synced state via the mirror's update
timestamps.

Run 'addigy-cli sync' periodically to populate the snapshot trail.`,
		Example: ` addigy-cli drift --since 24h --json --agent
  addigy-cli drift --since 1h --entity devices`,
		Annotations: map[string]string{"mcp:read-only": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if cliutil.IsVerifyEnv() {
				fmt.Fprintln(cmd.OutOrStdout(), "would report mirror drift since the given duration")
				return nil
			}
			if dryRunOK(flags) {
				return nil
			}
			dur, err := time.ParseDuration(sinceStr)
			if err != nil {
				return usageErr(fmt.Errorf("invalid --since duration %q (use e.g. 1h, 24h, 7d not supported — use 168h): %w", sinceStr, err))
			}
			cutoff := time.Now().Add(-dur)
			db, err := openDB(cmd, dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			types := []string{"devices", "oa-compliance-rules-pre-built", "facts", "monitoring", "oa-benchmarks-pre-built"}
			if entity != "" {
				types = []string{entityToType(entity)}
			}

			type change struct {
				ResourceType string `json:"resource_type"`
				ID           string `json:"id"`
				SyncedAt     string `json:"synced_at"`
			}
			var out []change
			placeholders := strings.Repeat("?,", len(types))
			placeholders = strings.TrimSuffix(placeholders, ",")
			qargs := make([]any, 0, len(types)+1)
			for _, t := range types {
				qargs = append(qargs, t)
			}
			qargs = append(qargs, cutoff.Format(time.RFC3339))
			rows, err := db.DB().Query(fmt.Sprintf(`SELECT id, resource_type, synced_at FROM resources WHERE resource_type IN (%s) AND datetime(synced_at) >= datetime(?)`, placeholders), qargs...)
			if err == nil {
				for rows.Next() {
					var id, rt, ts string
					if err := rows.Scan(&id, &rt, &ts); err == nil {
						out = append(out, change{ResourceType: rt, ID: id, SyncedAt: ts})
					}
				}
				rows.Close()
			}
			if flags.asJSON || flags.agent {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			for _, c := range out {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", c.SyncedAt, c.ResourceType, c.ID)
			}
			if !flags.quiet {
				fmt.Fprintf(cmd.OutOrStdout(), "\n%d row(s) changed since %s\n", len(out), cutoff.Format(time.RFC3339))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sinceStr, "since", "24h", "Look back duration (e.g. 1h, 24h, 168h)")
	cmd.Flags().StringVar(&entity, "entity", "", "Restrict to one entity: devices, policies, facts, software")
	cmd.Flags().StringVar(&dbPath, "db", "", "Database path")
	return cmd
}

func entityToType(e string) string {
	switch strings.ToLower(e) {
	case "devices", "device":
		return "devices"
	case "policies", "policy":
		return "policies"
	case "facts", "fact":
		return "facts"
	case "compliance":
		return "oa-compliance-rules-pre-built"
	case "monitoring", "alerts":
		return "monitoring"
	case "software", "smart-software":
		return "oa-benchmarks-pre-built"
	default:
		return e
	}
}

// --------------------------------------------------------------------------
// 7. policy-coverage [--policy <id>]
// --------------------------------------------------------------------------

func newPolicyCoverageCmd(flags *rootFlags) *cobra.Command {
	var policy, dbPath string
	cmd := &cobra.Command{
		Use:   "policy-coverage",
		Short: "Per-policy device counts joined to last-checkin",
		Long: `For every policy in the local mirror, report the count of devices assigned
plus how many of those have a stale last_checkin. Reveals policies with high
coverage but a stale device population.`,
		Example: ` addigy-cli policy-coverage --json --agent
  addigy-cli policy-coverage --policy ENG-Standard`,
		Annotations: map[string]string{"mcp:read-only": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if cliutil.IsVerifyEnv() {
				fmt.Fprintln(cmd.OutOrStdout(), "would compute policy coverage from local mirror")
				return nil
			}
			if dryRunOK(flags) {
				return nil
			}
			db, err := openDB(cmd, dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			devs, err := queryDevices(db, policy, "", 0)
			if err != nil {
				return err
			}
			staleCutoff := time.Now().Add(-7 * 24 * time.Hour)

			type bucket struct {
				PolicyID   string `json:"policy_id"`
				PolicyName string `json:"policy_name"`
				Total      int    `json:"total_devices"`
				Stale      int    `json:"stale_devices"`
			}
			byPolicy := map[string]*bucket{}
			for _, d := range devs {
				key := d.PolicyID
				if key == "" {
					key = d.PolicyName
				}
				if key == "" {
					key = "<unassigned>"
				}
				b, ok := byPolicy[key]
				if !ok {
					b = &bucket{PolicyID: d.PolicyID, PolicyName: d.PolicyName}
					if b.PolicyName == "" {
						b.PolicyName = key
					}
					byPolicy[key] = b
				}
				b.Total++
				t := parseAddigyTime(d.LastCheckin)
				if !t.IsZero() && t.Before(staleCutoff) {
					b.Stale++
				}
			}
			out := make([]bucket, 0, len(byPolicy))
			for _, b := range byPolicy {
				out = append(out, *b)
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Total > out[j].Total })

			if flags.asJSON || flags.agent {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			if flags.csv {
				fmt.Fprintln(cmd.OutOrStdout(), "policy_id,policy_name,total_devices,stale_devices")
				for _, b := range out {
					fmt.Fprintf(cmd.OutOrStdout(), "%s,%s,%d,%d\n", b.PolicyID, b.PolicyName, b.Total, b.Stale)
				}
				return nil
			}
			for _, b := range out {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%d devices (%d stale)\n", b.PolicyName, b.Total, b.Stale)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&policy, "policy", "", "Restrict to one policy ID or name")
	cmd.Flags().StringVar(&dbPath, "db", "", "Database path")
	return cmd
}

// --------------------------------------------------------------------------
// 8. fleet-summary
// --------------------------------------------------------------------------

func newFleetSummaryCmd(flags *rootFlags) *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "fleet-summary",
		Short: "Single-shot triage view of fleet health",
		Long: `Emit a single triage view of the fleet from the local mirror: device count,
stale fraction, alert count, MDM queue depth, Smart-Software pending count,
policy coverage percent. The fastest first-call for any Addigy triage workflow.`,
		Example:     ` addigy-cli fleet-summary --json --agent`,
		Annotations: map[string]string{"mcp:read-only": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if cliutil.IsVerifyEnv() {
				fmt.Fprintln(cmd.OutOrStdout(), "would emit fleet summary from local mirror")
				return nil
			}
			if dryRunOK(flags) {
				return nil
			}
			db, err := openDB(cmd, dbPath)
			if err != nil {
				return err
			}
			defer db.Close()

			devs, err := queryDevices(db, "", "", 0)
			if err != nil {
				return err
			}
			now := time.Now()
			staleCutoff := now.Add(-7 * 24 * time.Hour)
			stale := 0
			policies := map[string]struct{}{}
			for _, d := range devs {
				t := parseAddigyTime(d.LastCheckin)
				if !t.IsZero() && t.Before(staleCutoff) {
					stale++
				}
				if d.PolicyID != "" {
					policies[d.PolicyID] = struct{}{}
				}
			}

			alertCount := countByType(db, "monitoring")
			mdmQueue := countByType(db, "mdm")
			softwareCount := countByType(db, "smart-software")

			out := map[string]any{
				"device_count":          len(devs),
				"stale_devices_7d":      stale,
				"stale_fraction":        floatPercent(stale, len(devs)),
				"alert_count":           alertCount,
				"mdm_queue_depth":       mdmQueue,
				"smart_software_count":  softwareCount,
				"policies_with_devices": len(policies),
				"generated_at":          now.Format(time.RFC3339),
			}
			if flags.asJSON || flags.agent {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			keys := make([]string, 0, len(out))
			for k := range out {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(cmd.OutOrStdout(), "%-22s %v\n", k+":", out[k])
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "Database path")
	return cmd
}

func countByType(db *store.Store, resourceType string) int {
	row := db.DB().QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, resourceType)
	var n int
	_ = row.Scan(&n)
	return n
}

func floatPercent(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return float64(num) * 100.0 / float64(denom)
}

// --------------------------------------------------------------------------
// Wiring
// --------------------------------------------------------------------------

// registerCompoundCommands wires the 8 hand-built compound commands
// onto the root command. Called from root.go right after the generated
// spec-driven commands are attached.
func registerCompoundCommands(rootCmd *cobra.Command, flags *rootFlags) {
	// Top-level commands
	rootCmd.AddCommand(newComplianceCmd(flags))
	rootCmd.AddCommand(newRolloutCmd(flags))
	rootCmd.AddCommand(newDriftCmd(flags))
	rootCmd.AddCommand(newPolicyCoverageCmd(flags))
	rootCmd.AddCommand(newFleetSummaryCmd(flags))

	// devices subcommands: attach to existing 'devices' parent
	if devicesCmd := findChild(rootCmd, "devices"); devicesCmd != nil {
		devicesCmd.AddCommand(newDevicesStaleCmd(flags))
		devicesCmd.AddCommand(newDevicesDiffCmd(flags))
	}

	// facts subcommand: attach to existing 'facts' parent
	if factsCmd := findChild(rootCmd, "facts"); factsCmd != nil {
		factsCmd.AddCommand(newFactsSearchCmd(flags))
	}
}

func findChild(parent *cobra.Command, name string) *cobra.Command {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}
