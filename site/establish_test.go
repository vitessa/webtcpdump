package site

import (
	"testing"
)

func TestSiteEstablish(t *testing.T) {

	var info netStatInfo

	info.Stats = nil
	if _, err := siteEstablish(info); err != nil {
		t.Error(err)
	}

	info.Stats = make([]netStat, 0)
	if _, err := siteEstablish(info); err != nil {
		t.Error(err)
	}

	info.Stats = make([]netStat, 10)
	if _, err := siteEstablish(info); err != nil {
		t.Error(err)
	}
}
