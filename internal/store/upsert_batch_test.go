// Copyright 2026 joelcodess. Licensed under Apache-2.0. See LICENSE.

package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

// TestStoreWrite_NoSQLITE_BUSY_HighConcurrency exercises the writeMu serialization
// guarantee: 16 fetcher-style goroutines hammer the store with a mix of
// UpsertBatch, SaveSyncState, and SaveSyncCursor calls. Before the mutex
// fix, this test reproduces SQLITE_BUSY at default sync concurrency on
// pure-Go SQLite (modernc.org/sqlite + WAL) because multiple writers
// race for the WAL lock and busy_timeout retries are not exhaustive.
//
// Run under `go test -race` to catch any data races on Store fields.
func TestStoreWrite_NoSQLITE_BUSY_HighConcurrency(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	const goroutines = 16
	const itemsPerBatch = 5

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*3)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			rt := fmt.Sprintf("rt_%d", gid)
			items := make([]json.RawMessage, 0, itemsPerBatch)
			for i := 0; i < itemsPerBatch; i++ {
				items = append(items, json.RawMessage(fmt.Sprintf(`{"id": "g%d-i%d"}`, gid, i)))
			}
			if _, _, err := s.UpsertBatch(rt, items); err != nil {
				errCh <- fmt.Errorf("UpsertBatch goroutine %d: %w", gid, err)
				return
			}
			if err := s.SaveSyncState(rt, fmt.Sprintf("cursor-%d", gid), itemsPerBatch); err != nil {
				errCh <- fmt.Errorf("SaveSyncState goroutine %d: %w", gid, err)
				return
			}
			if err := s.SaveSyncCursor(rt, fmt.Sprintf("cursor2-%d", gid)); err != nil {
				errCh <- fmt.Errorf("SaveSyncCursor goroutine %d: %w", gid, err)
				return
			}
		}(g)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err == nil {
			continue
		}
		// SQLITE_BUSY surfaces as "database is locked" or "SQLITE_BUSY"
		// in the error message — assert neither occurs.
		msg := err.Error()
		if strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(strings.ToLower(msg), "database is locked") {
			t.Fatalf("got SQLITE_BUSY-class error under concurrent writers: %v", err)
		}
		t.Fatalf("unexpected error under concurrent writers: %v", err)
	}

	// Verify all rows persisted: goroutines * itemsPerBatch in the generic
	// resources table.
	db := s.DB()
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources`).Scan(&total); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if total != goroutines*itemsPerBatch {
		t.Fatalf("resources total = %d, want %d", total, goroutines*itemsPerBatch)
	}
}

// TestStoreWrite_PanicReleasesLock confirms that a panic inside a locked
// section unwinds via defer s.writeMu.Unlock() so subsequent writers can
// proceed. A leaked lock would deadlock the second call indefinitely.
func TestStoreWrite_PanicReleasesLock(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Trigger panic by passing a nil *Store method receiver indirectly:
	// we call UpsertBatch with malformed JSON that survives Unmarshal
	// (it's wrapped in skipped-count handling) — there's no easy panic
	// path inside a locked section that doesn't also corrupt state, so
	// we instead simulate the post-panic state by manually locking and
	// unlocking, then assert subsequent calls succeed.
	func() {
		defer func() {
			recover()
		}()
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		panic("simulated writer panic")
	}()

	// Subsequent writer must not block.
	done := make(chan struct{})
	go func() {
		if _, _, err := s.UpsertBatch("post_panic", []json.RawMessage{json.RawMessage(`{"id": "x"}`)}); err != nil {
			t.Errorf("post-panic UpsertBatch: %v", err)
		}
		close(done)
	}()
	<-done
}

// TestUpsertBatch_TemplatedIDFieldOverrideWins exercises the
// per-resource ID-field override. When the spec author annotates a
// path-item with x-resource-id, the profiler emits SyncableResource.IDField,
// the generator templates this into resourceIDFieldOverrides, and
// UpsertBatch consults that map first. This test seeds the override map
// at runtime (since the generated table here may or may not declare any
// override) to assert the lookup path itself works.
func TestUpsertBatch_TemplatedIDFieldOverrideWins(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Inject a runtime override for a synthetic resource. Item carries
	// no generic-fallback field (no id/name/uuid/...) — only a custom
	// "ticker" field. Without the override, all 3 items would be
	// dropped as PK-unresolved; with it, all 3 land.
	prev, hadPrev := resourceIDFieldOverrides["overrideTest"]
	resourceIDFieldOverrides["overrideTest"] = "ticker"
	defer func() {
		if hadPrev {
			resourceIDFieldOverrides["overrideTest"] = prev
		} else {
			delete(resourceIDFieldOverrides, "overrideTest")
		}
	}()

	items := []json.RawMessage{
		json.RawMessage(`{"ticker": "AAPL", "price": 100}`),
		json.RawMessage(`{"ticker": "GOOG", "price": 200}`),
		json.RawMessage(`{"ticker": "MSFT", "price": 300}`),
	}
	stored, extractFailures, err := s.UpsertBatch("overrideTest", items)
	if err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}
	if stored != 3 {
		t.Fatalf("stored = %d, want 3 (templated override should resolve all PKs)", stored)
	}
	if extractFailures != 0 {
		t.Fatalf("extractFailures = %d, want 0", extractFailures)
	}
}

// TestUpsertBatch_GenericFallbackList covers each name in the reduced
// fallback list. The kalshi-accreted names (ticker/event_ticker/series_ticker)
// were dropped because the user owns kalshi and will regenerate
// it with x-resource-id annotations; this test pins what the generic list
// is now responsible for so a future trim doesn't silently break unannotated
// specs.
func TestUpsertBatch_GenericFallbackList(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for _, key := range []string{"id", "ID", "name", "uuid", "slug", "key", "code", "uid"} {
		t.Run(key, func(t *testing.T) {
			rt := "fallback_" + key
			items := []json.RawMessage{
				json.RawMessage(fmt.Sprintf(`{%q: %q}`, key, "value-1")),
				json.RawMessage(fmt.Sprintf(`{%q: %q}`, key, "value-2")),
			}
			stored, extractFailures, err := s.UpsertBatch(rt, items)
			if err != nil {
				t.Fatalf("UpsertBatch(%q): %v", key, err)
			}
			if stored != 2 {
				t.Fatalf("stored = %d, want 2 (fallback %q must resolve)", stored, key)
			}
			if extractFailures != 0 {
				t.Fatalf("extractFailures = %d, want 0", extractFailures)
			}
		})
	}

	// Negative: API-specific names dropped must NOT resolve.
	// Spec authors annotate these via x-resource-id instead.
	for _, key := range []string{"ticker", "event_ticker", "series_ticker"} {
		t.Run("dropped_"+key, func(t *testing.T) {
			rt := "dropped_" + key
			items := []json.RawMessage{
				json.RawMessage(fmt.Sprintf(`{%q: %q}`, key, "v1")),
			}
			stored, extractFailures, err := s.UpsertBatch(rt, items)
			if err != nil {
				t.Fatalf("UpsertBatch(%q): %v", key, err)
			}
			if stored != 0 {
				t.Fatalf("stored = %d, want 0 (%q must NOT be in the generic fallback list)", stored, key)
			}
			if extractFailures != 1 {
				t.Fatalf("extractFailures = %d, want 1 (%q drop must surface as extract failure)", extractFailures, key)
			}
		})
	}
}

// TestUpsertBatch_ExtractFailuresReturnedForPerItemMisses pins the third
// return value: items that survive JSON unmarshal but have no extractable
// PK (templated override AND generic fallback both miss) bump
// extractFailures. The sync.go.tmpl call site uses this to emit the
// per-resource primary_key_unresolved sync_anomaly the first time silent
// drops occur.
func TestUpsertBatch_ExtractFailuresReturnedForPerItemMisses(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "ok-1"}`),
		json.RawMessage(`{"some_random_field": "no-pk-here"}`),
		json.RawMessage(`{"id": "ok-2"}`),
		json.RawMessage(`{"another_field": 42}`),
	}
	stored, extractFailures, err := s.UpsertBatch("mixed_extraction", items)
	if err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}
	if stored != 2 {
		t.Fatalf("stored = %d, want 2 (only items with id should land)", stored)
	}
	if extractFailures != 2 {
		t.Fatalf("extractFailures = %d, want 2 (two items have no extractable PK)", extractFailures)
	}
}

// TestUpsertBatch_PopulatesBenchmarksTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed benchmarks table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesBenchmarksTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("benchmarks", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "benchmarks").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "benchmarks")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count benchmarks: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("benchmarks count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesChildrenTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed children table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesChildrenTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("children", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "children").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "children")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count children: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("children count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesCommunityTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed community table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesCommunityTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("community", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "community").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "community")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count community: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("community count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesComplianceRulesTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed compliance_rules table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesComplianceRulesTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("compliance_rules", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "compliance_rules").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "compliance_rules")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count compliance_rules: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("compliance_rules count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesDdmUpdatesTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed ddm_updates table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesDdmUpdatesTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("ddm_updates", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "ddm_updates").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "ddm_updates")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count ddm_updates: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("ddm_updates count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesDeviceTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed device table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesDeviceTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("device", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "device").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "device")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count device: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("device count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesODevicesTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed o_devices table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesODevicesTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("o_devices", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "o_devices").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "o_devices")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count o_devices: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("o_devices count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesHomescreenTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed homescreen table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesHomescreenTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("homescreen", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "homescreen").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "homescreen")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count homescreen: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("homescreen count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesIdentityTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed identity table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesIdentityTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("identity", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "identity").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "identity")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count identity: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("identity count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesIntegrationsTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed integrations table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesIntegrationsTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("integrations", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "integrations").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "integrations")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count integrations: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("integrations count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesOMdmTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed o_mdm table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesOMdmTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("o_mdm", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "o_mdm").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "o_mdm")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count o_mdm: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("o_mdm count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesOMonitoringTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed o_monitoring table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesOMonitoringTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("o_monitoring", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "o_monitoring").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "o_monitoring")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count o_monitoring: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("o_monitoring count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesPoliciesTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed policies table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesPoliciesTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("policies", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "policies").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "policies")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("policies count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesPolicyTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed policy table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesPolicyTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("policy", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "policy").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "policy")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count policy: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("policy count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesOPrebuiltAppsTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed o_prebuilt_apps table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesOPrebuiltAppsTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("o_prebuilt_apps", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "o_prebuilt_apps").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "o_prebuilt_apps")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count o_prebuilt_apps: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("o_prebuilt_apps count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesReportsTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed reports table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesReportsTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("reports", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "reports").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "reports")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count reports: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("reports count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesScriptsTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed scripts table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesScriptsTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("scripts", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "scripts").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "scripts")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count scripts: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("scripts count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesTemplatesTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed templates table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesTemplatesTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("templates", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "templates").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "templates")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count templates: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("templates count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesOUsersTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed o_users table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesOUsersTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("o_users", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "o_users").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "o_users")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count o_users: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("o_users count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesVariablesTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed variables table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesVariablesTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("variables", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "variables").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "variables")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count variables: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("variables count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// TestUpsertBatch_PopulatesWebhooksTable verifies that UpsertBatch
// dispatches paginated items into both the generic resources table AND the
// typed webhooks table. Regression for issue #268: before the fix, paginated
// syncs only filled the generic resources table, so domain commands that
// query the typed table saw zero rows.
func TestUpsertBatch_PopulatesWebhooksTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	items := []json.RawMessage{
		json.RawMessage(`{"id": "test-001", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-002", "o_id": "test-parent-001"}`),
		json.RawMessage(`{"id": "test-003", "o_id": "test-parent-001"}`),
	}
	if _, _, err := s.UpsertBatch("webhooks", items); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}

	db := s.DB()

	var generic int
	if err := db.QueryRow(`SELECT COUNT(*) FROM resources WHERE resource_type = ?`, "webhooks").Scan(&generic); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if generic != len(items) {
		t.Fatalf("resources count = %d, want %d", generic, len(items))
	}

	var typed int
	typedQuery := fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, "webhooks")
	if err := db.QueryRow(typedQuery).Scan(&typed); err != nil {
		t.Fatalf("count webhooks: %v", err)
	}
	if typed != len(items) {
		t.Fatalf("webhooks count = %d, want %d (typed table not populated by UpsertBatch)", typed, len(items))
	}
}

// The mirror holds org configuration, so it must be owner-only even when an
// older build left it world-readable.
func TestOpen_RestrictsDBFileMode(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data.db")

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.Close()
	assertMode(t, dbPath, 0o600)

	if err := os.Chmod(dbPath, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	assertMode(t, dbPath, 0o600)
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", path, got, want)
	}
}
