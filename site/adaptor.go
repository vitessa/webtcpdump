package site

import (
	"bytes"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sort"
)

type adaptorInfo struct {
	Adaptors []adaptor
}

type adaptor struct {
	Idx  int
	Name string
	IPv4 string
	IPv6 string
	MTU  int
}

func getActivatedNetDevice() (adaptors []adaptor, err error) {
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
		var ipv4, ipv6 string
		if addrs, err := ifc.Addrs(); err != nil {
			continue
		} else {
			for _, addr := range addrs {
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					continue
				}
				if ip.To4() != nil {
					ipv4 = ip.To4().String()
				} else if ip.To16() != nil {
					ipv6 = ip.To16().String()
				}
			}
		}

		adaptors = append(adaptors, adaptor{Idx: ifc.Index, Name: ifc.Name, IPv4: ipv4, IPv6: ipv6, MTU: ifc.MTU})
	}

	// 排序
	sort.Slice(adaptors, func(i, j int) bool { return adaptors[i].Idx < adaptors[j].Idx })

	return
}

func siteAdaptor(info adaptorInfo) ([]byte, error) {
	var data bytes.Buffer

	if tmpl, err := template.New("tmplAdaptor").Parse(tmplAdaptor); err != nil {
		return nil, err
	} else if err := tmpl.Execute(&data, info); err != nil {
		return nil, err
	}

	return data.Bytes(), nil
}

func OnAdaptor(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		var info adaptorInfo

		if adaptors, err := getActivatedNetDevice(); err != nil {
			fmt.Fprintf(w, err.Error())
		} else {
			info.Adaptors = adaptors
		}

		if data, err := siteAdaptor(info); err != nil {
			fmt.Fprintf(w, err.Error())
		} else {
			w.Write(data)
		}
	}
}
