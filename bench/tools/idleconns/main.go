// idleconns opens N connections to an nginx server, completes one request on
// each, then keeps them all open (idle keep-alive) until stdin is closed.
// It prints "READY <ok> <failed>" once every connection is established, so a
// harness can measure the server's memory per idle connection.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

func dial(mode, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	switch mode {
	case "h1":
		return d.Dial("tcp", addr)
	case "tls", "h2":
		proto := "http/1.1"
		if mode == "h2" {
			proto = "h2"
		}
		c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{proto},
			ServerName:         "localhost",
		})
		if err != nil {
			return nil, err
		}
		if c.ConnectionState().NegotiatedProtocol != proto {
			c.Close()
			return nil, fmt.Errorf("ALPN negotiated %q", c.ConnectionState().NegotiatedProtocol)
		}
		return c, nil
	}
	return nil, fmt.Errorf("unknown mode %s", mode)
}

func h1Request(c net.Conn, path string) error {
	if _, err := io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err == nil && resp.StatusCode != 200 {
		err = fmt.Errorf("status %d", resp.StatusCode)
	}
	return err
}

func frame(typ, flags byte, stream uint32, payload []byte) []byte {
	b := make([]byte, 9+len(payload))
	b[0], b[1], b[2] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
	b[3], b[4] = typ, flags
	binary.BigEndian.PutUint32(b[5:], stream)
	copy(b[9:], payload)
	return b
}

func h2Request(c net.Conn, path string) error {
	// HPACK: :method GET, :scheme https, :path <path>, :authority localhost
	hb := []byte{0x82, 0x87, 0x04, byte(len(path))}
	hb = append(hb, path...)
	hb = append(hb, 0x01, 9)
	hb = append(hb, "localhost"...)
	out := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	out = append(out, frame(4, 0, 0, nil)...)
	out = append(out, frame(1, 0x5, 1, hb)...)
	if _, err := c.Write(out); err != nil {
		return err
	}
	r := bufio.NewReader(c)
	hdr := make([]byte, 9)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return err
		}
		n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ, flags := hdr[3], hdr[4]
		stream := binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
		if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
			return err
		}
		switch typ {
		case 4: // SETTINGS
			if flags&1 == 0 {
				if _, err := c.Write(frame(4, 1, 0, nil)); err != nil {
					return err
				}
			}
		case 3, 7: // RST_STREAM, GOAWAY
			return errors.New("stream reset / goaway")
		case 0, 1: // DATA, HEADERS
			if stream == 1 && flags&1 != 0 {
				return nil
			}
		}
	}
}

func main() {
	mode := flag.String("mode", "h1", "h1 | tls | h2")
	addr := flag.String("addr", "127.0.0.1:18080", "server address")
	n := flag.Int("n", 10000, "connections")
	path := flag.String("path", "/1k.bin", "request path")
	par := flag.Int("par", 100, "parallel dialers")
	flag.Parse()

	conns := make([]net.Conn, *n)
	sem := make(chan struct{}, *par)
	var wg sync.WaitGroup
	var mu sync.Mutex
	fails := 0
	var firstErr error
	for i := 0; i < *n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := dial(*mode, *addr)
			if err == nil {
				if *mode == "h2" {
					err = h2Request(c, *path)
				} else {
					err = h1Request(c, *path)
				}
				if err != nil {
					c.Close()
				}
			}
			if err != nil {
				mu.Lock()
				fails++
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			conns[i] = c
		}(i)
	}
	wg.Wait()
	if firstErr != nil {
		fmt.Fprintln(os.Stderr, "first error:", firstErr)
	}
	fmt.Printf("READY %d %d\n", *n-fails, fails)
	os.Stdout.Sync()
	io.Copy(io.Discard, os.Stdin)
	for _, c := range conns {
		if c != nil {
			c.Close()
		}
	}
}
