package site

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

var (
	form_key_port     string = "port"
	form_key_src_addr string = "SrcAddr"
	form_key_src_port string = "SrcPort"
	form_key_dst_addr string = "DstAddr"
	form_key_dst_port string = "DstPort"
)

func OnIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {

		tmpl, err := template.New("tmplIndex").Parse(tmplIndex)
		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}

		if err = tmpl.Execute(w, nil); err != nil {
			log.Println(err.Error())
			return
		}
	}
}
