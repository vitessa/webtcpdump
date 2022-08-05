package sniff

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestPrasePacket(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{}
	eth := layers.Ethernet{SrcMAC: make([]byte, 6), DstMAC: make([]byte, 6)}
	ip4 := layers.IPv4{SrcIP: net.IPv4zero, DstIP: net.IPv4zero}
	ip6 := layers.IPv6{SrcIP: net.IPv6zero, DstIP: net.IPv6zero}

	// IPv4
	if err := gopacket.SerializeLayers(buf, opt, &eth, &ip4, &layers.TCP{}, gopacket.Payload([]byte{1, 2, 3, 4})); err != nil {
		t.Error(err)
	} else if _, _, _, _, err := PrasePacket(gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)); err != nil {
		t.Error(err)
	}

	// IPv6
	if err := gopacket.SerializeLayers(buf, opt, &eth, &ip6, &layers.TCP{}, gopacket.Payload([]byte{1, 2, 3, 4})); err != nil {
		t.Error(err)
	} else if _, _, _, _, err := PrasePacket(gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)); err != nil {
		t.Error(err)
	}
}
