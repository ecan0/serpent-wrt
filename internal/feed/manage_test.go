package feed_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ecan0/serpent-wrt/internal/feed"
)

func TestNormalizeEntry(t *testing.T) {
	cases := []struct {
		in       string
		wantVal  string
		wantType string
	}{
		{" 1.2.3.4 ", "1.2.3.4", "ip"},
		{"10.0.0.1", "10.0.0.1", "ip"},
		{"5.6.7.9/24", "5.6.7.0/24", "cidr"},
	}
	for _, tc := range cases {
		got, err := feed.NormalizeEntry(tc.in)
		if err != nil {
			t.Fatalf("NormalizeEntry(%q): %v", tc.in, err)
		}
		if got.Value != tc.wantVal || got.Type != tc.wantType {
			t.Fatalf("NormalizeEntry(%q): got %+v, want value=%q type=%q", tc.in, got, tc.wantVal, tc.wantType)
		}
	}
}

func TestNormalizeEntryRejectsInvalid(t *testing.T) {
	for _, in := range []string{"", "# comment", "not-an-ip", "::1", "2001:db8::/32"} {
		if _, err := feed.NormalizeEntry(in); err == nil {
			t.Fatalf("NormalizeEntry(%q): expected error", in)
		}
	}
}

func TestListFile(t *testing.T) {
	path := writeFeed(t, `
# keep me
1.2.3.4
5.6.7.9/24
`)
	snap, err := feed.ListFile(path)
	if err != nil {
		t.Fatalf("ListFile: %v", err)
	}
	if snap.Path != path || snap.Count != 2 || snap.MaxEntries != feed.MaxManagedEntries {
		t.Fatalf("snapshot metadata: %+v", snap)
	}
	if snap.Entries[0].Value != "1.2.3.4" || snap.Entries[1].Value != "5.6.7.0/24" {
		t.Fatalf("entries: %+v", snap.Entries)
	}
}

func TestListFileRejectsMalformedLine(t *testing.T) {
	path := writeFeed(t, "1.2.3.4\nbad\n")
	_, err := feed.ListFile(path)
	if err == nil {
		t.Fatal("expected malformed line error")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error: got %q, want line context", err)
	}
}

func TestValidateEntriesDeduplicatesAndPreservesOrder(t *testing.T) {
	snap, err := feed.ValidateEntries([]string{"5.6.7.0/24", "1.2.3.4", "1.2.3.4"})
	if err != nil {
		t.Fatalf("ValidateEntries: %v", err)
	}
	if snap.Count != 2 {
		t.Fatalf("count: got %d, want 2", snap.Count)
	}
	if snap.Entries[0].Value != "5.6.7.0/24" || snap.Entries[1].Value != "1.2.3.4" {
		t.Fatalf("entries: %+v", snap.Entries)
	}
}

func TestAddFileEntryPreservesComments(t *testing.T) {
	path := writeFeed(t, "# comment\n1.2.3.4\n")
	res, err := feed.AddFileEntry(path, "5.6.7.8")
	if err != nil {
		t.Fatalf("AddFileEntry: %v", err)
	}
	if !res.Changed || res.Count != 2 {
		t.Fatalf("result: %+v", res)
	}
	got := readFile(t, path)
	if got != "# comment\n1.2.3.4\n5.6.7.8\n" {
		t.Fatalf("file:\ngot  %q\nwant %q", got, "# comment\n1.2.3.4\n5.6.7.8\n")
	}
}

func TestAddFileEntryDuplicateNoOp(t *testing.T) {
	path := writeFeed(t, "1.2.3.4\n")
	res, err := feed.AddFileEntry(path, "1.2.3.4")
	if err != nil {
		t.Fatalf("AddFileEntry: %v", err)
	}
	if res.Changed || res.Count != 1 {
		t.Fatalf("result: %+v", res)
	}
	if got := readFile(t, path); got != "1.2.3.4\n" {
		t.Fatalf("file changed: %q", got)
	}
}

func TestRemoveFileEntry(t *testing.T) {
	path := writeFeed(t, "# comment\n1.2.3.4\n5.6.7.0/24\n1.2.3.4\n")
	res, err := feed.RemoveFileEntry(path, "1.2.3.4")
	if err != nil {
		t.Fatalf("RemoveFileEntry: %v", err)
	}
	if !res.Changed || res.Count != 1 {
		t.Fatalf("result: %+v", res)
	}
	if got := readFile(t, path); got != "# comment\n5.6.7.0/24\n" {
		t.Fatalf("file: %q", got)
	}
}

func TestRemoveFileEntryMissingNoOp(t *testing.T) {
	path := writeFeed(t, "1.2.3.4\n")
	res, err := feed.RemoveFileEntry(path, "5.6.7.8")
	if err != nil {
		t.Fatalf("RemoveFileEntry: %v", err)
	}
	if res.Changed || res.Count != 1 {
		t.Fatalf("result: %+v", res)
	}
}

func TestReplaceFileEntries(t *testing.T) {
	path := writeFeed(t, "# old\n1.2.3.4\n")
	res, err := feed.ReplaceFileEntries(path, []string{"5.6.7.9/24", "1.2.3.4", "1.2.3.4"})
	if err != nil {
		t.Fatalf("ReplaceFileEntries: %v", err)
	}
	if !res.Changed || res.Count != 2 {
		t.Fatalf("result: %+v", res)
	}
	if got := readFile(t, path); got != "5.6.7.0/24\n1.2.3.4\n" {
		t.Fatalf("file: %q", got)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
