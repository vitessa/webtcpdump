package site

import "testing"

func TestSiteAdaptor(t *testing.T) {

	var info adaptorInfo

	info.Adaptors = nil
	if _, err := siteAdaptor(info); err != nil {
		t.Error(err)
	}

	info.Adaptors = make([]adaptor, 0)
	if _, err := siteAdaptor(info); err != nil {
		t.Error(err)
	}

	info.Adaptors = make([]adaptor, 10)
	if _, err := siteAdaptor(info); err != nil {
		t.Error(err)
	}
}
