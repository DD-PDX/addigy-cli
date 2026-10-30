// Hand-authored sync extensions for the DD-PDX fork. Not generated.
//
// The generated sync loop only knows flat GET list endpoints, so the local
// mirror never received the resources the compound commands read (policies,
// smart software, scripts, ...). Addigy serves most of those from read-only
// POST .../query searches, org-scoped /o/{org}/ paths, or per-policy GETs.
// This file holds the request shapes for those resources (copied from the
// Automa_Addigy_Tracking exporter's EndpointProbe list, verified 2026-10-29),
// org-id resolution, the per-policy dependent sync, and the secret redaction
// applied to every item before it is written to the mirror.

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/joelcodess/addigy-cli/internal/client"
	"github.com/joelcodess/addigy-cli/internal/store"
)

// syncClient is the subset of *client.Client the sync loop uses. PostQuery
// refuses any path that does not end in /query (except the exact device
// search path, POST /devices), which keeps sync read-only.
type syncClient interface {
	Get(string, map[string]string) (json.RawMessage, error)
	PostQuery(string, map[string]string, any) (json.RawMessage, int, error)
	RateLimit() float64
}

// syncEnv carries run-wide context that individual resource paths need.
// A nil *syncEnv is valid and means "no org id known".
type syncEnv struct {
	OrgID string
}

// orgPathKey is the placeholder org-scoped sync paths use for the org id.
const orgPathKey = "{org}"

// syncQuerySpec describes a resource synced through a read-only POST .../query
// search. Body is sent on every page with page/per_page overwritten; Params
// go on the query string (Addigy's oa/ searches need multitenancy=false to
// stay inside the key's own org).
type syncQuerySpec struct {
	Params map[string]string
	Body   map[string]any
}

// sortedQueryBody mirrors SORTED_QUERY_BODY in the tracking exporter: the oa/
// policies and smart-software searches reject a body without sort fields.
func sortedQueryBody() map[string]any {
	return map[string]any{"sort_direction": "asc", "sort_field": "name"}
}

var oaQueryParams = map[string]string{"multitenancy": "false"}

// syncQuerySpecs is keyed by sync resource name. A resource listed here is
// fetched with PostQuery instead of Get.
var syncQuerySpecs = map[string]syncQuerySpec{
	"benchmarks":              {Params: oaQueryParams, Body: map[string]any{}},
	"compliance-rules":        {Params: oaQueryParams, Body: map[string]any{}},
	"devices":                 {Body: map[string]any{}},
	"policies":                {Params: oaQueryParams, Body: sortedQueryBody()},
	"smart-software":          {Params: oaQueryParams, Body: sortedQueryBody()},
	"scripts":                 {Body: map[string]any{}},
	"variables":               {Params: oaQueryParams, Body: map[string]any{}},
	"webhooks":                {Params: oaQueryParams, Body: map[string]any{}},
	"maintenance":             {Body: map[string]any{}},
	"identity-configurations": {Params: oaQueryParams, Body: map[string]any{}},
}

// syncQueryPageSize is the per_page sent to /query searches. Addigy caps
// most searches well above this; the scripts search requires page >= 1.
const syncQueryPageSize = 100

// syncDependentSpec describes a resource fetched once per parent row, e.g.
// GET /system-updates/settings?policy_id=<policyId> for every synced policy.
type syncDependentSpec struct {
	Parent     string // parent resource whose mirrored ids drive the calls
	ParentID   string // query parameter that receives each parent id
	ParentName string // parent field copied onto each child row for readability
	NameAs     string // child field that receives the parent's ParentName value
}

var syncDependentSpecs = map[string]syncDependentSpec{
	"system-update-settings": {Parent: "policies", ParentID: "policy_id", ParentName: "name", NameAs: "policy_name"},
}

// syncParentResources run before everything else: their rows supply the org
// id for /o/{org}/ paths and the parent ids for dependent resources.
var syncParentResources = []string{"policies"}

// orderSyncResources splits the requested resources into the three phases
// newSyncCmd runs in order: parents, flat resources, then dependents.
func orderSyncResources(resources []string) (parents, flat, dependents []string) {
	isParent := map[string]bool{}
	for _, p := range syncParentResources {
		isParent[p] = true
	}
	for _, r := range resources {
		switch {
		case isParent[r]:
			parents = append(parents, r)
		case syncDependentSpecs[r] != (syncDependentSpec{}):
			dependents = append(dependents, r)
		default:
			flat = append(flat, r)
		}
	}
	return parents, flat, dependents
}

// needsOrgID reports whether any of the resources has an org-scoped path.
func needsOrgID(resources []string) bool {
	for _, r := range resources {
		if p, err := syncResourcePath(r); err == nil && strings.Contains(p, orgPathKey) {
			return true
		}
	}
	return false
}

// resolveSyncOrgID returns the org id for /o/{org}/ paths: the --org-id flag,
// then ADDIGY_ORG_ID, then the orgid recorded on any mirrored policy. Returns
// "" when none is available; org-scoped resources are then skipped with the
// usual unfilled_path_key warning.
func resolveSyncOrgID(flagValue string, db *store.Store) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("ADDIGY_ORG_ID")); v != "" {
		return v
	}
	if db == nil {
		return ""
	}
	var org string
	_ = db.DB().QueryRow(`SELECT COALESCE(json_extract(data, '$.orgid'), json_extract(data, '$.organization_id'), '')
		FROM resources WHERE resource_type = 'policies' AND COALESCE(json_extract(data, '$.orgid'), json_extract(data, '$.organization_id'), '') != '' LIMIT 1`).Scan(&org)
	return org
}

// resolveSyncPath fills run-wide placeholders in a sync path.
func resolveSyncPath(path string, env *syncEnv) string {
	if env != nil && env.OrgID != "" {
		path = strings.ReplaceAll(path, orgPathKey, env.OrgID)
	}
	return path
}

// fetchSyncPage fetches one page of a resource. GET resources keep the
// generated cursor pagination (params already carry per_page/after); /query
// resources page by number in the body.
func fetchSyncPage(c syncClient, resource, path string, params map[string]string, page int) (json.RawMessage, error) {
	spec, ok := syncQuerySpecs[resource]
	if !ok {
		return c.Get(path, params)
	}
	body := make(map[string]any, len(spec.Body)+2)
	for k, v := range spec.Body {
		body[k] = v
	}
	body["page"] = page
	body["per_page"] = syncQueryPageSize
	data, _, err := c.PostQuery(path, spec.Params, body)
	return data, err
}

// queryPageCount reads metadata.page_count from an Addigy /query envelope.
// Responses without it (policies and webhooks return a bare array holding
// every row) count as a single page.
func queryPageCount(data json.RawMessage) int {
	var env struct {
		Metadata struct {
			PageCount int `json:"page_count"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &env); err != nil || env.Metadata.PageCount < 1 {
		return 1
	}
	return env.Metadata.PageCount
}

// syncDependentResource fetches one row per parent id. A parent that answers
// 404 (deleted since the parent sync) is skipped rather than failing the run.
func syncDependentResource(c syncClient, db *store.Store, resource string, env *syncEnv, concurrency int) syncResult {
	started := time.Now()
	spec := syncDependentSpecs[resource]

	if !humanFriendly {
		fmt.Fprintf(os.Stdout, `{"event":"sync_start","resource":"%s"}`+"\n", resource)
	}

	path, err := syncResourcePath(resource)
	if err != nil {
		return syncResult{Resource: resource, Err: err, Duration: time.Since(started)}
	}
	path = resolveSyncPath(path, env)

	parents, err := loadParentRows(db, spec)
	if err != nil {
		return syncResult{Resource: resource, Err: fmt.Errorf("loading %s ids: %w", spec.Parent, err), Duration: time.Since(started)}
	}
	if len(parents) == 0 {
		return syncResult{Resource: resource, Warn: fmt.Errorf("skipped %s: no %s in the local mirror; sync %s first", resource, spec.Parent, spec.Parent), Duration: time.Since(started)}
	}

	if concurrency < 1 {
		concurrency = 4
	}
	type fetched struct {
		item json.RawMessage
		err  error
	}
	work := make(chan parentRow)
	out := make(chan fetched)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				data, err := c.Get(path, map[string]string{spec.ParentID: p.ID})
				if err != nil {
					out <- fetched{err: err}
					continue
				}
				item, err := prepareDependentItem(resource, spec, p, data)
				out <- fetched{item: item, err: err}
			}
		}()
	}
	go func() {
		for _, p := range parents {
			work <- p
		}
		close(work)
		wg.Wait()
		close(out)
	}()

	var items []json.RawMessage
	var notFound int
	var firstErr error
	for f := range out {
		switch {
		case f.err == nil:
			items = append(items, f.item)
		case isNotFound(f.err):
			notFound++
		case firstErr == nil:
			firstErr = f.err
		}
	}
	if firstErr != nil {
		if w, ok := isSyncAccessWarning(firstErr); ok {
			return syncResult{Resource: resource, Warn: fmt.Errorf("skipped %s: %s", resource, w.Reason), Duration: time.Since(started)}
		}
		return syncResult{Resource: resource, Err: fmt.Errorf("fetching %s: %w", resource, firstErr), Duration: time.Since(started)}
	}

	stored, _, err := upsertResourceBatch(db, resource, items)
	if err != nil {
		return syncResult{Resource: resource, Err: fmt.Errorf("upserting batch for %s: %w", resource, err), Duration: time.Since(started)}
	}
	_ = db.SaveSyncState(resource, "", stored)
	if notFound > 0 && humanFriendly {
		fmt.Fprintf(os.Stderr, "  %s: %d %s no longer exist upstream (404), skipped\n", resource, notFound, spec.Parent)
	}
	if !humanFriendly {
		fmt.Fprintf(os.Stdout, `{"event":"sync_complete","resource":"%s","total":%d,"duration_ms":%d}`+"\n", resource, stored, time.Since(started).Milliseconds())
	}
	return syncResult{Resource: resource, Count: stored, Duration: time.Since(started)}
}

type parentRow struct {
	ID   string
	Name string
}

func loadParentRows(db *store.Store, spec syncDependentSpec) ([]parentRow, error) {
	rows, err := db.DB().Query(`SELECT id, COALESCE(json_extract(data, '$.'||?), '') FROM resources WHERE resource_type = ? ORDER BY id`, spec.ParentName, spec.Parent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []parentRow
	for rows.Next() {
		var p parentRow
		if err := rows.Scan(&p.ID, &p.Name); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// prepareDependentItem tags a child row with its parent's id (the row's
// primary key) and name, then applies the usual redaction.
func prepareDependentItem(resource string, spec syncDependentSpec, p parentRow, data json.RawMessage) (json.RawMessage, error) {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("decoding %s for %s %s: %w", resource, spec.Parent, p.ID, err)
	}
	if _, ok := obj[spec.ParentID]; !ok {
		obj[spec.ParentID] = p.ID
	}
	if p.Name != "" && spec.NameAs != "" {
		obj[spec.NameAs] = p.Name
	}
	return prepareSyncObject(resource, obj)
}

func isNotFound(err error) bool {
	var apiErr *client.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == 404
}

// --------------------------------------------------------------------------
// Redaction
// --------------------------------------------------------------------------

// redactedValue replaces secret values. The key is kept so queries can still
// tell that a secret is configured.
const redactedValue = "REDACTED"

// syncRedactKeys lists, per resource, keys whose values are always replaced
// wherever they appear in a row (matching the tracking exporter's
// always_redact sets).
var syncRedactKeys = map[string][]string{
	"webhooks":  {"secret_token", "url", "headers"},
	"variables": {"default_value", "value", "values"},
}

// syncSecretKeyResources get pattern-based redaction of any credential-shaped
// key (client_secret, api_token, Password, Challenge, ...) at any depth.
var syncSecretKeyResources = map[string]bool{
	"identity-configurations":     true,
	"mdm":                         true,
	"mdm-configurations-profiles": true,
	"webhooks":                    true,
	"variables":                   true,
}

// secretKeyRE matches credential-shaped key names once lower-cased with "_"
// and "-" removed. Keys ending in id/uuid/type name or classify a secret
// rather than hold one and are left alone (see isSecretKey).
var secretKeyRE = regexp.MustCompile(`password|passwd|passphrase|secret|token|challenge|apikey|privatekey|sharedkey|psk`)

func isSecretKey(key string) bool {
	k := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
	if strings.HasSuffix(k, "id") || strings.HasSuffix(k, "uuid") || strings.HasSuffix(k, "type") {
		return false
	}
	return secretKeyRE.MatchString(k)
}

// redactSyncObject scrubs secrets from one decoded row in place. It reports
// whether anything was replaced.
func redactSyncObject(resource string, obj map[string]any) bool {
	always := map[string]bool{}
	for _, k := range syncRedactKeys[resource] {
		always[k] = true
	}
	byPattern := syncSecretKeyResources[resource]
	if len(always) == 0 && !byPattern {
		return false
	}
	return redactValue(obj, always, byPattern)
}

func redactValue(v any, always map[string]bool, byPattern bool) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		// A PKCS#12 payload carries the private key in its content blob.
		if pt, _ := t["payload_type"].(string); strings.Contains(strings.ToLower(pt), "pkcs12") {
			for _, k := range []string{"payload_content", "PayloadContent"} {
				if _, ok := t[k]; ok {
					t[k] = redactedValue
					changed = true
				}
			}
		}
		for k, child := range t {
			if always[k] || (byPattern && isSecretKey(k)) {
				if child != nil && child != "" {
					t[k] = redactedValue
					changed = true
				}
				continue
			}
			if redactValue(child, always, byPattern) {
				changed = true
			}
		}
	case []any:
		for _, child := range t {
			if redactValue(child, always, byPattern) {
				changed = true
			}
		}
	}
	return changed
}

// syncCompositeIDs gives a primary key to resources whose rows have none of
// their own: the listed fields are joined with ":" into an "id" field.
var syncCompositeIDs = map[string][]string{
	// One row per (script, device) pair; script.id in the payload is empty.
	"device-script-assignments": {"script_id", "agent_id"},
}

// syncOrgKeyedResources have generated typed tables keyed by a NOT NULL
// o_id column (from the /o/{o_id}/... spec shapes), but the rows Addigy
// returns carry the org as orgid or organization_id. Without o_id the typed
// insert fails and takes the whole batch with it.
var syncOrgKeyedResources = map[string]bool{
	"benchmarks": true,
	"policies":   true,
	"scripts":    true,
	"variables":  true,
	"webhooks":   true,
}

// prepareSyncObject applies composite ids, the o_id copy and redaction to a
// decoded row and re-encodes it.
func prepareSyncObject(resource string, obj map[string]any) (json.RawMessage, error) {
	if syncOrgKeyedResources[resource] {
		if _, has := obj["o_id"]; !has {
			org := ""
			for _, k := range []string{"orgid", "organization_id", "org_id"} {
				if v, ok := obj[k].(string); ok && v != "" {
					org = v
					break
				}
			}
			obj["o_id"] = org
		}
	}
	if fields, ok := syncCompositeIDs[resource]; ok {
		if _, has := obj["id"]; !has {
			parts := make([]string, 0, len(fields))
			for _, f := range fields {
				if v, ok := obj[f]; ok && v != nil && fmt.Sprint(v) != "" {
					parts = append(parts, fmt.Sprint(v))
				}
			}
			if len(parts) == len(fields) {
				obj["id"] = strings.Join(parts, ":")
			}
		}
	}
	redactSyncObject(resource, obj)
	if !syncTextRedactionExempt[resource] {
		redactSecretsDeep(obj, "")
	}
	return json.Marshal(obj)
}

// prepareSyncItems runs prepareSyncObject over a page of items. Items that
// are not JSON objects pass through untouched (UpsertBatch skips them).
func prepareSyncItems(resource string, items []json.RawMessage) []json.RawMessage {
	if !syncNeedsPrepare(resource) {
		return items
	}
	out := make([]json.RawMessage, len(items))
	for i, item := range items {
		out[i] = prepareSyncItem(resource, item)
	}
	return out
}

// prepareSyncItem is prepareSyncObject for a raw item. Anything that is not a
// JSON object is returned unchanged.
func prepareSyncItem(resource string, item json.RawMessage) json.RawMessage {
	if !syncNeedsPrepare(resource) {
		return item
	}
	var obj map[string]any
	if err := json.Unmarshal(item, &obj); err != nil || obj == nil {
		return item
	}
	prepared, err := prepareSyncObject(resource, obj)
	if err != nil {
		// Fail closed: an item that could not be re-encoded after redaction
		// is dropped (UpsertBatch skips undecodable items) rather than stored raw.
		return nil
	}
	return prepared
}

// syncNeedsPrepare reports whether rows of resource must be decoded and
// rewritten before upsert. Every resource except the public catalogs gets the
// text-level secret scan, so this is false only for those.
func syncNeedsPrepare(resource string) bool {
	return !syncTextRedactionExempt[resource]
}
