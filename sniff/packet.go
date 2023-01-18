package sniff

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |     |N|C|E|U|A|P|R|S|F|                               |
   | Offset|     | |W|C|R|C|S|S|Y|I|            Window             |
   |       |     |S|R|E|G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           [Options]                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               :
   :                             Data                              :
   :                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

func PrasePacket(packet gopacket.Packet) (srcAddr net.IP, dstAddr net.IP, tcp layers.TCP, payload gopacket.Payload, err error) {
	var (
		eth layers.Ethernet
		lb  layers.Loopback
		ip4 layers.IPv4
		ip6 layers.IPv6
	)

	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerArray(nil)).
		Put(&eth).
		Put(&lb).
		Put(&ip4).
		Put(&ip6).
		Put(&tcp).
		Put(&payload)
	decoded := []gopacket.LayerType{}
	
	// 尝试Ethernet和Loopback
	for _, firstLayer := range [...]gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeLoopback} {
		// 开始解码
		decoder := dlc.LayersDecoder(firstLayer, gopacket.NilDecodeFeedback)
		if lt, e := decoder(packet.Data(), &decoded); e != nil {
			continue
		} else if lt != gopacket.LayerTypeZero {
			continue
		} else if len(decoded) <= 1 {
			continue
		}
	}

	if len(decoded) <= 1 {
		err = errors.New("PrasePacket error: decode failed")
		return
	}

	// 取地址
	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeIPv6:
			tcp.SetNetworkLayerForChecksum(&ip6)
			src, dst := ip6.NetworkFlow().Endpoints()
			srcAddr = src.Raw()
			dstAddr = dst.Raw()
		case layers.LayerTypeIPv4:
			tcp.SetNetworkLayerForChecksum(&ip4)
			src, dst := ip4.NetworkFlow().Endpoints()
			srcAddr = net.IPv4(src.Raw()[0], src.Raw()[1], src.Raw()[2], src.Raw()[3])
			dstAddr = net.IPv4(dst.Raw()[0], dst.Raw()[1], dst.Raw()[2], dst.Raw()[3])
		}
	}

	return
}

func PrasePacketToString(packet gopacket.Packet) string {
	srcAddr, dstAddr, tcp, payload, err := PrasePacket(packet)
	if err != nil {
		msg := fmt.Sprintf("Could not decode layers: %v", err)
		return msg
	}
	// 拼接
	strFlow := fmt.Sprintf("%s:%d -> %s:%d", srcAddr, tcp.SrcPort, dstAddr, tcp.DstPort)

	// 取位标志
	var flags []string
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	if tcp.ECE {
		flags = append(flags, "ECE")
	}
	if tcp.CWR {
		flags = append(flags, "CWR")
	}
	if tcp.NS {
		flags = append(flags, "NS")
	}
	strFlag := strings.Replace(fmt.Sprint(flags), " ", ",", -1)

	// 时间戳
	t := packet.Metadata().Timestamp
	timestamp := fmt.Sprintf("[%02d:%02d:%02d:%03d]", t.Hour(), t.Minute(), t.Second(), t.Nanosecond()/1000000)

	// 本地地址，手动计算ChkSum
	if IsLocalAddr(srcAddr) {
		tcp.BaseLayer.Contents[16], tcp.BaseLayer.Contents[17] = 0, 0
		if cs, err := tcp.ComputeChecksum(); err != nil {
			// 程序错误
			return fmt.Sprintf("%s %-10s check sum error", strFlow, strFlag)
		} else {
			// 标准写法
			//	csum := uint32(tcp.Checksum) + uint32(cs)
			//	for csum > 0xffff {
			//		csum = (csum >> 16) + (csum & 0xffff)
			//	}
			//	tcp.Checksum = uint16(csum)
			//	tcp.BaseLayer.Contents[16] = byte(csum >> 8)
			//	tcp.BaseLayer.Contents[17] = byte(csum)
			//
			// 由于前面给chksum清0了，这么写也可以
			tcp.Checksum = cs
			tcp.BaseLayer.Contents[16] = byte(cs >> 8)
			tcp.BaseLayer.Contents[17] = byte(cs)
		}
	}

	// 校验 TCP 的 Checksum 字段
	if cs, err := tcp.ComputeChecksum(); err != nil {
		// 程序错误
		return fmt.Sprintf("%s %s %-10s Seq=%08x Ack=%08x check sum error %s", timestamp, strFlow, strFlag, tcp.Seq, tcp.Ack, err.Error())
	} else if cs != 0 {
		// TCP 校验失败
		return fmt.Sprintf("%s %s %-10s Seq=%08x Ack=%08x check sum failed", timestamp, strFlow, strFlag, tcp.Seq, tcp.Ack)
	}

	// TCP信息
	strInfo := fmt.Sprintf(
		"%-10s Seq=%08x Ack=%08x chksum=%04x Win=%d Len=%d",
		strFlag,
		tcp.Seq,
		tcp.Ack,
		tcp.Checksum,
		tcp.Window,
		len(payload),
	)

	// Option 信息
	strOption := ""
	options := []string{}
	for _, op := range tcp.Options {
		if op.OptionType == layers.TCPOptionKindNop {
			continue
		}
		options = append(options, TcpOptionToString(op))
	}
	if len(options) > 0 {
		sort.Slice(options, func(i, j int) bool { return options[i] < options[j] })
		strOption = fmt.Sprintf("Option=%v", options)
	}

	// 负载
	strDump := hex.Dump(payload)
	if strDump != "" {
		strDump = strings.Trim(strDump, "\n")
		strDump = "\n" + strDump
		strDump = strings.Replace(strDump, "\n", "\n               ", -1)
	}

	return fmt.Sprintf("%s %s %s %s %s", timestamp, strFlow, strInfo, strOption, strDump)
}
