package runtime

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ecan0/serpent-wrt/internal/config"
	"github.com/ecan0/serpent-wrt/internal/events"
)

func TestFeedManagementAddRemoveReplace(t *testing.T) {
	path := writeRuntimeFeed(t, "1.2.3.4\n")
	e := NewEngine(feedManagementConfig(path), events.NewLogger(nil))
	if err := e.ReloadFeed(); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	if e.feed.Len() != 1 {
		t.Fatalf("initial feed len: got %d, want 1", e.feed.Len())
	}

	added, err := e.AddFeedEntry("5.6.7.8")
	if err != nil {
		t.Fatalf("AddFeedEntry: %v", err)
	}
	if !added.Changed || added.Count != 2 || e.feed.Len() != 2 {
		t.Fatalf("add result=%+v feed_len=%d", added, e.feed.Len())
	}

	duplicate, err := e.AddFeedEntry("5.6.7.8")
	if err != nil {
		t.Fatalf("AddFeedEntry duplicate: %v", err)
	}
	if duplicate.Changed || duplicate.Count != 2 || e.feed.Len() != 2 {
		t.Fatalf("duplicate result=%+v feed_len=%d", duplicate, e.feed.Len())
	}

	removed, err := e.RemoveFeedEntry("1.2.3.4")
	if err != nil {
		t.Fatalf("RemoveFeedEntry: %v", err)
	}
	if !removed.Changed || removed.Count != 1 || e.feed.Len() != 1 {
		t.Fatalf("remove result=%+v feed_len=%d", removed, e.feed.Len())
	}

	replaced, err := e.ReplaceFeedEntries([]string{"9.9.9.9", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ReplaceFeedEntries: %v", err)
	}
	if !replaced.Changed || replaced.Count != 2 || e.feed.Len() != 2 {
		t.Fatalf("replace result=%+v feed_len=%d", replaced, e.feed.Len())
	}
}

func TestFeedManagementListAndValidate(t *testing.T) {
	path := writeRuntimeFeed(t, "# comment\n1.2.3.4\n")
	e := NewEngine(feedManagementConfig(path), events.NewLogger(nil))

	snap, err := e.ListFeedEntries()
	if err != nil {
		t.Fatalf("ListFeedEntries: %v", err)
	}
	if snap.Path != path || snap.Count != 1 || snap.Entries[0].Value != "1.2.3.4" {
		t.Fatalf("snapshot: %+v", snap)
	}

	validated, err := e.ValidateFeedEntries([]string{"5.6.7.9/24"})
	if err != nil {
		t.Fatalf("ValidateFeedEntries: %v", err)
	}
	if validated.Count != 1 || validated.Entries[0].Value != "5.6.7.0/24" {
		t.Fatalf("validated: %+v", validated)
	}
}

func feedManagementConfig(path string) *config.Config {
	cfg := testConfig()
	cfg.ThreatFeedPath = path
	cfg.PollInterval = 5 * time.Second
	return cfg
}

func writeRuntimeFeed(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "threat-feed.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
