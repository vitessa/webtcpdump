package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
	"github.com/vitessa/webtcpdump/site"
)

var (
	host string
	port uint64
)

func init() {
	flag.StringVar(&host, "n", "", "listen port for webtcpdump")
	flag.Uint64Var(&port, "p", 8000, "listen port for webtcpdump")
	flag.Parse()
}

func main() {
	// 注册路由
	http.HandleFunc("/", site.OnIndex)
	http.HandleFunc("/adaptor", site.OnAdaptor)
	http.HandleFunc("/listen", site.OnListen)
	http.HandleFunc("/establish", site.OnEstablish)
	http.HandleFunc("/tcpsniff", site.OnTcpSniff)

	// 监听地址
	addr := fmt.Sprintf("%s:%d", host, port)
	srv := &http.Server{
		Addr:         addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Println("listen:", addr)

	waitServerShutdown := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)

		// 等待中断信号
		<-sigint
		log.Println("shutdown...")

		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(waitServerShutdown)
	}()

	// 开始监听
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-waitServerShutdown
}
