package site

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"sort"

	"github.com/vitessa/go-netstat/netstat"
)

type netStatInfo struct {
	Stats []netStat
}

type netStat struct {
	Idx     int
	SrcAddr string
	SrcPort uint16
	DstAddr string
	DstPort uint16
	State   string
	Pid     int
	Program string
}

func getListenStat() ([]netStat, error) {
	stats := []netStat{}

	// 所有监听端口
	tcp4, err := netstat.TCPSocks(
		func(s *netstat.SockTabEntry) bool {
			return s.State == netstat.Listen
		})
	if err != nil {
		return nil, err
	}
	tcp6, err := netstat.TCP6Socks(
		func(s *netstat.SockTabEntry) bool {
			return s.State == netstat.Listen
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
			Pid:     sock.Process.Pid,
			Program: sock.Process.Name,
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
			Pid:     sock.Process.Pid,
			Program: sock.Process.Name,
		}
		stats = append(stats, stat)
	}
	// 排序
	sort.Slice(stats, func(i, j int) bool { return stats[i].SrcPort < stats[j].SrcPort })
	for idx := range stats {
		stats[idx].Idx = idx + 1
	}

	return stats, nil
}

func siteListen(info netStatInfo) ([]byte, error) {
	var data bytes.Buffer

	if tmpl, err := template.New("tmplListen").Parse(tmplListen); err != nil {
		return nil, err
	} else if err := tmpl.Execute(&data, info); err != nil {
		return nil, err
	}

	return data.Bytes(), nil
}

func OnListen(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		var info netStatInfo

		// 解析参数、网络信息
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, err.Error())
		} else if stats, err := getListenStat(); err != nil {
			fmt.Fprintf(w, err.Error())
		} else {
			info.Stats = stats
		}

		// 解析模板，发送信息
		if data, err := siteListen(info); err != nil {
			fmt.Fprintf(w, err.Error())
		} else {
			w.Write(data)
		}
	}
}
