package site

import (
	"testing"
)

func TestSiteTcpSniff(t *testing.T) {
	var info tcpSniffInfo
	if _, err := siteTcpSniff(info); err != nil {
		t.Error(err)
	}
}
