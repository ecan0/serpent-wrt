package runtime

import "github.com/ecan0/serpent-wrt/internal/feed"

// ListFeedEntries returns the normalized local threat feed file.
func (e *Engine) ListFeedEntries() (feed.Snapshot, error) {
	e.feedFileMu.Lock()
	defer e.feedFileMu.Unlock()
	return feed.ListFile(e.cfg.ThreatFeedPath)
}

// ValidateFeedEntries validates a candidate replacement feed without writing it.
func (e *Engine) ValidateFeedEntries(entries []string) (feed.Snapshot, error) {
	return feed.ValidateEntries(entries)
}

// AddFeedEntry appends one entry to the local threat feed, then reloads if changed.
func (e *Engine) AddFeedEntry(entry string) (feed.UpdateResult, error) {
	e.feedFileMu.Lock()
	defer e.feedFileMu.Unlock()

	result, err := feed.AddFileEntry(e.cfg.ThreatFeedPath, entry)
	if err != nil {
		return feed.UpdateResult{}, err
	}
	if result.Changed {
		if err := e.reloadFeedLocked(); err != nil {
			return feed.UpdateResult{}, err
		}
	}
	return result, nil
}

// RemoveFeedEntry removes one entry from the local threat feed, then reloads if changed.
func (e *Engine) RemoveFeedEntry(entry string) (feed.UpdateResult, error) {
	e.feedFileMu.Lock()
	defer e.feedFileMu.Unlock()

	result, err := feed.RemoveFileEntry(e.cfg.ThreatFeedPath, entry)
	if err != nil {
		return feed.UpdateResult{}, err
	}
	if result.Changed {
		if err := e.reloadFeedLocked(); err != nil {
			return feed.UpdateResult{}, err
		}
	}
	return result, nil
}

// ReplaceFeedEntries replaces the local threat feed, then reloads it.
func (e *Engine) ReplaceFeedEntries(entries []string) (feed.UpdateResult, error) {
	e.feedFileMu.Lock()
	defer e.feedFileMu.Unlock()

	result, err := feed.ReplaceFileEntries(e.cfg.ThreatFeedPath, entries)
	if err != nil {
		return feed.UpdateResult{}, err
	}
	if err := e.reloadFeedLocked(); err != nil {
		return feed.UpdateResult{}, err
	}
	return result, nil
}
