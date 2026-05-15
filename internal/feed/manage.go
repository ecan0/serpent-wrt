package feed

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// MaxManagedEntries bounds feed management API writes for router-sized devices.
const MaxManagedEntries = 20000

// Entry is a normalized threat feed entry.
type Entry struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

// Snapshot describes the feed file as normalized entries.
type Snapshot struct {
	Path       string  `json:"path,omitempty"`
	Count      int     `json:"count"`
	MaxEntries int     `json:"max_entries"`
	Entries    []Entry `json:"entries"`
}

// UpdateResult summarizes a feed file mutation.
type UpdateResult struct {
	Path    string `json:"path"`
	Count   int    `json:"count"`
	Changed bool   `json:"changed"`
}

type managedLine struct {
	raw   string
	entry Entry
	ok    bool
}

// NormalizeEntry validates and canonicalizes one IPv4 or IPv4 CIDR feed entry.
func NormalizeEntry(value string) (Entry, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Entry{}, fmt.Errorf("entry is required")
	}
	if strings.HasPrefix(value, "#") {
		return Entry{}, fmt.Errorf("comments are not feed entries")
	}
	if strings.Contains(value, "/") {
		ip, ipnet, err := net.ParseCIDR(value)
		if err != nil || ip.To4() == nil {
			return Entry{}, fmt.Errorf("entry must be an IPv4 address or CIDR, got %q", value)
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			return Entry{}, fmt.Errorf("entry must be an IPv4 CIDR, got %q", value)
		}
		network := ip.Mask(ipnet.Mask).To4()
		if network == nil {
			return Entry{}, fmt.Errorf("entry must be an IPv4 CIDR, got %q", value)
		}
		return Entry{Value: fmt.Sprintf("%s/%d", network.String(), ones), Type: "cidr"}, nil
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return Entry{}, fmt.Errorf("entry must be an IPv4 address or CIDR, got %q", value)
	}
	return Entry{Value: ip.To4().String(), Type: "ip"}, nil
}

// ListFile returns normalized entries from a feed file, failing on malformed
// non-comment lines so management callers do not silently preserve bad data.
func ListFile(path string) (Snapshot, error) {
	lines, err := readManagedLines(path)
	if err != nil {
		return Snapshot{}, err
	}
	entries := entriesFromLines(lines)
	return Snapshot{
		Path:       path,
		Count:      len(entries),
		MaxEntries: MaxManagedEntries,
		Entries:    entries,
	}, nil
}

// ValidateEntries validates and canonicalizes a candidate replacement feed.
func ValidateEntries(values []string) (Snapshot, error) {
	entries, err := normalizeEntries(values)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Count:      len(entries),
		MaxEntries: MaxManagedEntries,
		Entries:    entries,
	}, nil
}

// AddFileEntry appends one normalized entry if it is not already present.
func AddFileEntry(path, value string) (UpdateResult, error) {
	entry, err := NormalizeEntry(value)
	if err != nil {
		return UpdateResult{}, err
	}
	lines, err := readManagedLines(path)
	if err != nil {
		return UpdateResult{}, err
	}
	entries := entriesFromLines(lines)
	for _, existing := range entries {
		if existing.Value == entry.Value {
			return UpdateResult{Path: path, Count: len(entries), Changed: false}, nil
		}
	}
	if len(entries) >= MaxManagedEntries {
		return UpdateResult{}, fmt.Errorf("feed entry limit exceeded: max %d", MaxManagedEntries)
	}

	out := renderExistingLines(lines)
	if len(out) > 0 && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += entry.Value + "\n"
	if err := writeFeedFile(path, out); err != nil {
		return UpdateResult{}, err
	}
	return UpdateResult{Path: path, Count: len(entries) + 1, Changed: true}, nil
}

// RemoveFileEntry removes all lines matching one normalized entry.
func RemoveFileEntry(path, value string) (UpdateResult, error) {
	entry, err := NormalizeEntry(value)
	if err != nil {
		return UpdateResult{}, err
	}
	lines, err := readManagedLines(path)
	if err != nil {
		return UpdateResult{}, err
	}
	before := entriesFromLines(lines)
	kept := lines[:0]
	removed := 0
	for _, line := range lines {
		if line.ok && line.entry.Value == entry.Value {
			removed++
			continue
		}
		kept = append(kept, line)
	}
	if removed == 0 {
		return UpdateResult{Path: path, Count: len(before), Changed: false}, nil
	}
	if err := writeFeedFile(path, renderExistingLines(kept)); err != nil {
		return UpdateResult{}, err
	}
	return UpdateResult{Path: path, Count: len(before) - removed, Changed: true}, nil
}

// ReplaceFileEntries atomically replaces the feed with normalized entries.
func ReplaceFileEntries(path string, values []string) (UpdateResult, error) {
	entries, err := normalizeEntries(values)
	if err != nil {
		return UpdateResult{}, err
	}
	var b strings.Builder
	for _, entry := range entries {
		b.WriteString(entry.Value)
		b.WriteByte('\n')
	}
	if err := writeFeedFile(path, b.String()); err != nil {
		return UpdateResult{}, err
	}
	return UpdateResult{Path: path, Count: len(entries), Changed: true}, nil
}

func normalizeEntries(values []string) ([]Entry, error) {
	if len(values) > MaxManagedEntries {
		return nil, fmt.Errorf("feed entry limit exceeded: max %d", MaxManagedEntries)
	}
	seen := make(map[string]Entry, len(values))
	var entries []Entry
	for i, value := range values {
		entry, err := NormalizeEntry(value)
		if err != nil {
			return nil, fmt.Errorf("entries[%d]: %w", i, err)
		}
		if _, ok := seen[entry.Value]; ok {
			continue
		}
		seen[entry.Value] = entry
		entries = append(entries, entry)
	}
	if len(entries) > MaxManagedEntries {
		return nil, fmt.Errorf("feed entry limit exceeded: max %d", MaxManagedEntries)
	}
	return entries, nil
}

func readManagedLines(path string) ([]managedLine, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open feed %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	var lines []managedLine
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, managedLine{raw: raw})
			continue
		}
		entry, err := NormalizeEntry(trimmed)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		lines = append(lines, managedLine{raw: raw, entry: entry, ok: true})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func entriesFromLines(lines []managedLine) []Entry {
	entries := make([]Entry, 0, len(lines))
	for _, line := range lines {
		if line.ok {
			entries = append(entries, line.entry)
		}
	}
	return entries
}

func renderExistingLines(lines []managedLine) string {
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line.raw)
		b.WriteByte('\n')
	}
	return b.String()
}

func writeFeedFile(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".serpent-feed-*")
	if err != nil {
		return fmt.Errorf("create temp feed: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp feed: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp feed: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod temp feed: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		if runtime.GOOS != "windows" {
			return fmt.Errorf("replace feed: %w", err)
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("remove feed before replace: %w", removeErr)
		}
		if renameErr := os.Rename(tmpName, path); renameErr != nil {
			return fmt.Errorf("replace feed after removing destination: %w", renameErr)
		}
	}
	return nil
}
