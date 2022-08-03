package site

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"
	"strconv"

	"github.com/vitessa/go-netstat/netstat"
)

func getPortStat(port uint16) ([]netStat, error) {
	stats := []netStat{}

	// 所有监听端口
	tcp4, err := netstat.TCPSocks(
		func(s *netstat.SockTabEntry) bool {
			return s.LocalAddr.Port == port
		})
	if err != nil {
		return nil, err
	}
	tcp6, err := netstat.TCP6Socks(
		func(s *netstat.SockTabEntry) bool {
			return s.LocalAddr.Port == port
		})
	if err != nil {
		return nil, err
	}

	for _, sock := range tcp4 {
		stat := netStat{
			Idx:     0,
			SrcAddr: sock.LocalAddr.IP.String(),
			SrcPort: sock.LocalAddr.Port,
			DstAddr: sock.RemoteAddr.IP.String(),
			DstPort: sock.RemoteAddr.Port,
			State:   sock.State.String(),
		}
		stats = append(stats, stat)
	}
	for _, sock := range tcp6 {
		stat := netStat{
			Idx:     0,
			SrcAddr: sock.LocalAddr.IP.String(),
			SrcPort: sock.LocalAddr.Port,
			DstAddr: sock.RemoteAddr.IP.String(),
			DstPort: sock.RemoteAddr.Port,
			State:   sock.State.String(),
		}
		stats = append(stats, stat)
	}

	// 排序
	sort.Slice(stats, func(i, j int) bool { return stats[i].DstPort < stats[j].DstPort })
	for idx := range stats {
		stats[idx].Idx = idx + 1
	}

	return stats, nil
}

func OnEstablish(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		port, err := strconv.Atoi(r.FormValue(form_key_port))
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}

		stats, err := getPortStat(uint16(port))
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}

		info := netStatInfo{
			Stats: stats,
		}

		tmpl, err := template.New("tmplEstablish").Parse(tmplEstablish)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}

		if err = tmpl.Execute(w, info); err != nil {
			log.Println(err.Error())
			return
		}
	}
}
