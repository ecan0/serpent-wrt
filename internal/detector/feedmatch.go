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
	if r.DstIP != nil && d.feed.Contains(r.DstIP) {
		return &Detection{
			Type:       "feed_match",
			Severity:   SeverityHigh,
			Confidence: 95,
			Reason:     ReasonThreatFeedDestination,
			SrcIP:      r.SrcIP,
			DstIP:      r.DstIP,
			DstPort:    r.DstPort,
			Message:    fmt.Sprintf("connection to threat feed entry %s", r.DstIP),
			At:         time.Now(),
		}
	}
	if translatedIP, translatedPort, translated := r.TranslatedDst(); translated && d.feed.Contains(translatedIP) {
		return &Detection{
			Type:              "feed_match",
			Severity:          SeverityHigh,
			Confidence:        95,
			Reason:            ReasonThreatFeedDestination,
			SrcIP:             r.SrcIP,
			DstIP:             r.DstIP,
			DstPort:           r.DstPort,
			TranslatedDstIP:   translatedIP,
			TranslatedDstPort: translatedPort,
			Message:           fmt.Sprintf("connection translated to threat feed entry %s", translatedIP),
			At:                time.Now(),
		}
	}
	if r.SrcIP != nil && d.feed.Contains(r.SrcIP) {
		return &Detection{
			Type:       "feed_match",
			Severity:   SeverityHigh,
			Confidence: 95,
			Reason:     ReasonThreatFeedSource,
			SrcIP:      r.SrcIP,
			DstIP:      r.DstIP,
			DstPort:    r.DstPort,
			Message:    fmt.Sprintf("connection from threat feed entry %s", r.SrcIP),
			At:         time.Now(),
		}
	}
	return nil
}
