package site

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"
	"webtcpdump/sniff"

	"github.com/gorilla/websocket"
)

type tcpSniffInfo struct {
	SrcAddr string
	SrcPort uint16
	DstAddr string
	DstPort uint16
}

func parseParam(r *http.Request) (tcpSniffInfo, error) {
	r.ParseForm()
	info := tcpSniffInfo{}

	info.SrcAddr = template.HTMLEscapeString(r.FormValue(form_key_src_addr))
	if info.SrcAddr == "" {
		return tcpSniffInfo{}, errors.New("empty src addr")
	}
	srcPort, err := strconv.Atoi(template.HTMLEscapeString(r.FormValue(form_key_src_port)))
	if err != nil {
		return tcpSniffInfo{}, errors.New("invalid src port")
	} else {
		info.SrcPort = uint16(srcPort)
	}
	info.DstAddr = template.HTMLEscapeString(r.FormValue(form_key_dst_addr))
	if info.DstAddr == "" {
		return tcpSniffInfo{}, errors.New("empty dst addr")
	}
	dstPort, err := strconv.Atoi(template.HTMLEscapeString(r.FormValue(form_key_dst_port)))
	if err != nil {
		return tcpSniffInfo{}, errors.New("invalid dst port")
	} else {
		info.DstPort = uint16(dstPort)
	}

	return info, nil
}

func OnTcpSniff(w http.ResponseWriter, r *http.Request) {
	if websocket.IsWebSocketUpgrade(r) {

		// 解析参数
		info, err := parseParam(r)
		if err != nil {
			log.Println(err.Error())
			return
		}

		// 创建通道
		messages := make(chan string)
		defer close(messages)
		done := make(chan struct{})
		defer close(done)

		// 连接 websocket
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 3145728, // 3MB
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err.Error())
			return
		}
		defer conn.Close()

		// 开始嗅探
		if info.DstPort == 0 {
			err := sniff.SniffNewSocket(info.SrcPort, messages, done)
			if err != nil {
				log.Println("SniffNewSocket", err.Error())
				return
			}
		} else {
			err := sniff.SniffSocket(info.SrcAddr, info.SrcPort, info.DstAddr, info.DstPort, messages, done)
			if err != nil {
				log.Println("SniffSocket", err.Error())
				return
			}
		}

		// 接收
		log.Printf("[sniff] client: %s, route:%s:%d->%s:%d", r.RemoteAddr, info.SrcAddr, info.SrcPort, info.DstAddr, info.DstPort)
		for {
			select {
			case message, ok := <-messages:
				if !ok {
					return
				}
				err := conn.WriteMessage(websocket.TextMessage, []byte(message))
				if err != nil {
					log.Println("WriteMessage", err.Error())
					return
				}
			case <-time.After(5 * time.Minute):
				return
			}
		}

	} else if r.Method == "GET" {
		info, err := parseParam(r)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}

		tmpl, err := template.New("tmplTcpSniff").Parse(tmplTcpSniff)
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
