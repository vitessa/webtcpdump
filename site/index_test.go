package site

import "testing"

func TestSiteIndex(t *testing.T) {
	if _, err := siteIndex(); err != nil {
		t.Error(err)
	}
}
