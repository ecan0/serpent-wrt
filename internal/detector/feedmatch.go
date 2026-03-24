package detector

import (
	"fmt"
	"time"

	"github.com/ecan0/serpent-wrt/internal/feed"
	"github.com/ecan0/serpent-wrt/internal/flow"
)

// FeedMatch detects connections to IPs or CIDRs listed in the threat feed.
type FeedMatch struct {
	feed *feed.Feed
}

func NewFeedMatch(f *feed.Feed) *FeedMatch {
	return &FeedMatch{feed: f}
}

func (d *FeedMatch) Check(r flow.FlowRecord) *Detection {
	if r.DstIP == nil || !d.feed.Contains(r.DstIP) {
		return nil
	}
	return &Detection{
		Type:    "feed_match",
		SrcIP:   r.SrcIP,
		DstIP:   r.DstIP,
		DstPort: r.DstPort,
		Message: fmt.Sprintf("connection to threat feed entry %s", r.DstIP),
		At:      time.Now(),
	}
}
