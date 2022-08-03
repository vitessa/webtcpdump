package sniff

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"strconv"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var SeqLocalAddr []net.IP

func init() {
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, ifc := range ifs {
		// 判断是否启用
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}

		// 转换 IPv4 和 IPv6
		if addrs, err := ifc.Addrs(); err != nil {
			continue
		} else {
			for _, addr := range addrs {
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					continue
				}
				SeqLocalAddr = append(SeqLocalAddr, ip)
			}
		}
	}
}

func bpfFilter(srcAddr string, srcPort uint16, dstAddr string, dstPort uint16) (string, error) {
	dict := map[string]string{}
	dict["SrcAddr"] = srcAddr
	dict["SrcPort"] = strconv.Itoa(int(srcPort))
	dict["DstAddr"] = dstAddr
	dict["DstPort"] = strconv.Itoa(int(dstPort))

	// 模板
	tmpl, err := template.New("bpf").
		Parse("tcp and ((src host {{.SrcAddr}} and src port {{.SrcPort}} and dst host {{.DstAddr}} and dst port {{.DstPort}}) or (dst host {{.SrcAddr}} and dst port {{.SrcPort}} and src host {{.DstAddr}} and src port {{.DstPort}}))")
	if err != nil {
		return "", err
	}

	// 替换参数
	var b bytes.Buffer
	if err = tmpl.Execute(&b, dict); err != nil {
		log.Println(err.Error())
		return "", err
	}

	// BPF
	bpf := b.String()

	return bpf, nil
}

func openAllDevs() ([]*pcap.Handle, error) {

	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return []*pcap.Handle{}, err
	} else if len(ifs) <= 0 {
		return []*pcap.Handle{}, errors.New("not find network device")
	}

	handles := []*pcap.Handle{}
	for _, ifc := range ifs {
		if len(ifc.Addresses) <= 0 {
			continue
		}

		inactive, err := pcap.NewInactiveHandle(ifc.Name)
		if err != nil {
			return []*pcap.Handle{}, err
		}
		defer inactive.CleanUp()

		// 配置
		if err := inactive.SetSnapLen(65535); err != nil {
			return []*pcap.Handle{}, err
		} else if err := inactive.SetPromisc(false); err != nil {
			return []*pcap.Handle{}, err
		} else if err := inactive.SetTimeout(pcap.BlockForever); err != nil {
			return []*pcap.Handle{}, err
		}

		// 激活
		handle, err := inactive.Activate() // after this, inactive is no longer valid
		if err != nil {
			return []*pcap.Handle{}, err
		}

		handles = append(handles, handle)
	}

	return handles, nil
}

func IsLocalAddr(ip net.IP) bool {
	for _, addr := range SeqLocalAddr {
		if addr.Equal(ip) {
			return true
		}
	}
	return false
}

func TcpOptionToString(op layers.TCPOption) string {
	hd := hex.EncodeToString(op.OptionData)
	if len(hd) > 0 {
		hd = ":0x" + hd
	}
	switch op.OptionType {
	case layers.TCPOptionKindMSS:
		if len(op.OptionData) >= 2 {
			return fmt.Sprintf("%s:%v",
				op.OptionType,
				binary.BigEndian.Uint16(op.OptionData))
		}

	case layers.TCPOptionKindTimestamps:
		if len(op.OptionData) == 8 {
			return fmt.Sprintf("%s:%v/%v%s",
				op.OptionType,
				binary.BigEndian.Uint32(op.OptionData[:4]),
				binary.BigEndian.Uint32(op.OptionData[4:8]),
				hd)
		}
	}
	return fmt.Sprintf("%s%s", op.OptionType, hd)
}
