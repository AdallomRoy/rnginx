// fcgiserver is a minimal FastCGI responder used as the fastcgi_pass backend:
// every request gets a fixed 1 KB application/octet-stream body.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"strings"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:19000", "listen address")
	flag.Parse()
	body := []byte(strings.Repeat("x", 1024))
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(fcgi.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(body)
	})))
}
