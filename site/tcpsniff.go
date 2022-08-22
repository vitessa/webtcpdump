package site

import (
	"bytes"
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

func parseSniffParam(r *http.Request) (tcpSniffInfo, error) {
	var info tcpSniffInfo

	if err := r.ParseForm(); err != nil {
		return info, err
	} else if srcAddr := template.HTMLEscapeString(r.FormValue(form_key_src_addr)); srcAddr == "" {
		return info, errors.New("empty src addr")
	} else if srcPort, err := strconv.Atoi(template.HTMLEscapeString(r.FormValue(form_key_src_port))); err != nil {
		return info, err
	} else if dstAddr := template.HTMLEscapeString(r.FormValue(form_key_dst_addr)); dstAddr == "" {
		return info, errors.New("empty dst addr")
	} else if dstPort, err := strconv.Atoi(template.HTMLEscapeString(r.FormValue(form_key_dst_port))); err != nil {
		return info, err
	} else {
		info.SrcAddr = srcAddr
		info.SrcPort = uint16(srcPort)
		info.DstAddr = dstAddr
		info.DstPort = uint16(dstPort)
	}

	return info, nil
}

func siteTcpSniff(info tcpSniffInfo) ([]byte, error) {
	var data bytes.Buffer

	if tmpl, err := template.New("tmplTcpSniff").Parse(tmplTcpSniff); err != nil {
		return nil, err
	} else if err := tmpl.Execute(&data, info); err != nil {
		return nil, err
	}

	return data.Bytes(), nil
}

func OnTcpSniff(w http.ResponseWriter, r *http.Request) {
	if websocket.IsWebSocketUpgrade(r) {

		// 解析参数
		info, err := parseSniffParam(r)
		if err != nil {
			log.Println(err.Error())
			return
		}

		// 创建通道
		messages := make(chan string)
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
			if err := sniff.SniffNewSocket(info.SrcPort, messages, done); err != nil {
				log.Println("SniffNewSocket", err.Error())
				return
			}
		} else {
			if err := sniff.SniffSocket(info.SrcAddr, info.SrcPort, info.DstAddr, info.DstPort, messages, done); err != nil {
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
		if info, err := parseSniffParam(r); err != nil {
			fmt.Fprintf(w, err.Error())
		} else if data, err := siteTcpSniff(info); err != nil {
			fmt.Fprintf(w, err.Error())
		} else {
			w.Write(data)
		}
	}
}
