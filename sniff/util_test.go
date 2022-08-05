package sniff

import (
	"testing"
)

func TestBPFFilter(t *testing.T) {
	if _, err := bpfFilter("127.0.0.1", 22, "127.0.0.1", 65535); err != nil {
		t.Error(err)
	}
}
