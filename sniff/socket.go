package sniff

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func SniffNewSocket(port uint16, ch chan<- string, done <-chan struct{}) error {
	handles, err := openAllDevs()
	if err != nil {
		return err
	}
	if len(handles) <= 0 {
		return errors.New("not find active network device")
	}

	for _, handle := range handles {
		// BPF
		bpf := fmt.Sprintf("tcp and port %d", port)
		if err := handle.SetBPFFilter(bpf); err != nil {
			return err
		}

		go func(handle *pcap.Handle) {
			defer func() { handle.Close() }()

			srcAddr, dstAddr, dstPort := net.IP{}, net.IP{}, uint16(0)
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packets := packetSource.Packets()

			for {
				select {
				case <-done:
					return
				case packet, ok := <-packets:
					if !ok {
						return
					}

					src, dst, tcp, _, err := PrasePacket(packet)
					if err != nil {
						return
					}

					if dstPort == 0 {
						if uint16(tcp.DstPort) != port || !tcp.SYN {
							break
						}

						// 关闭其他设备
						for _, ele := range handles {
							if ele != handle {
								ele.Close()
							}
						}

						// 转新的 BPF
						if bpf, err := bpfFilter(dst.String(), uint16(tcp.DstPort), src.String(), uint16(tcp.SrcPort)); err != nil {
							break
						} else if err := handle.SetBPFFilter(bpf); err != nil {
							log.Println(err.Error())
							log.Panicln(bpf)
							break
						}

						srcAddr, dstAddr, dstPort = dst, src, uint16(tcp.SrcPort)
					} else {
						ok := (srcAddr.Equal(src) && port == uint16(tcp.SrcPort) && dstAddr.Equal(dst) && dstPort == uint16(tcp.DstPort)) ||
							(srcAddr.Equal(dst) && port == uint16(tcp.DstPort) && dstAddr.Equal(src) && dstPort == uint16(tcp.SrcPort))
						if !ok {
							break
						}
					}

					message := PrasePacketToString(packet)
					select {
					case <-done:
					case ch <- message:
					}
				}
			}
		}(handle)
	}

	return nil
}

func SniffSocket(srcAddr string, srcPort uint16, dstAddr string, dstPort uint16, ch chan<- string, done <-chan struct{}) error {
	bpf, err := bpfFilter(srcAddr, srcPort, dstAddr, dstPort)
	if err != nil {
		return err
	}

	handles, err := openAllDevs()
	if err != nil {
		return err
	}
	if len(handles) <= 0 {
		return errors.New("not find active network device")
	}

	for _, handle := range handles {
		if err := handle.SetBPFFilter(bpf); err != nil {
			return errors.New("set bpf filter error")
		}
		go func(handle *pcap.Handle) {
			defer func() {
				// 关闭所有设备
				for _, handle := range handles {
					handle.Close()
				}
			}()

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packets := packetSource.Packets()
			for {
				select {
				case <-done:
					return
				case packet, ok := <-packets:
					if !ok {
						return
					}

					message := PrasePacketToString(packet)
					select {
					case <-done:
					case ch <- message:
					}
				}
			}
		}(handle)
	}

	return nil
}
