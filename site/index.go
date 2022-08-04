package site

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
)

var (
	form_key_port     string = "port"
	form_key_src_addr string = "SrcAddr"
	form_key_src_port string = "SrcPort"
	form_key_dst_addr string = "DstAddr"
	form_key_dst_port string = "DstPort"
)

func siteIndex() ([]byte, error) {
	var data bytes.Buffer

	if tmpl, err := template.New("tmplIndex").Parse(tmplIndex); err != nil {
		return nil, err
	} else if err := tmpl.Execute(&data, nil); err != nil {
		return nil, err
	}

	return data.Bytes(), nil
}

func OnIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {

		if data, err := siteIndex(); err != nil {
			fmt.Fprintf(w, err.Error())
		} else {
			w.Write(data)
		}
	}
}
