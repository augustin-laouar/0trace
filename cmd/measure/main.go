// measure connects to an HTTP or HTTPS target and uses 0trace to estimate
// the RTT to the remote host.
//
// Usage:
//
//	sudo ./measure http://example.com
//	sudo ./measure https://example.com
//
// Requires root (or CAP_NET_RAW on Linux).
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/augustin-laouar/zerotrace"
)

func main() {
	rawURL := "http://example.com"
	if len(os.Args) > 1 {
		rawURL = os.Args[1]
		if !strings.Contains(rawURL, "://") {
			rawURL = "http://" + rawURL
		}
	}

	conn, err := dial(rawURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send a GET request to establish real traffic flow so NAT mappings stay
	// alive during the 0trace probing window.
	host := mustHostname(rawURL)
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", host)

	fmt.Printf("traceroute to %s\n", rawURL)
	hops, err := zerotrace.Traceroute(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if len(hops) == 0 {
		fmt.Println("no response")
		return
	}
	for _, h := range hops {
		if h.IP == nil {
			fmt.Printf("%3d  * * *\n", h.TTL)
		} else {
			fmt.Printf("%3d  %-15s  %d ms\n", h.TTL, h.IP, h.RTT.Milliseconds())
		}
	}
}

func dial(rawURL string) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	switch u.Scheme {
	case "https":
		if port == "" {
			port = "443"
		}
		return tls.Dial("tcp", net.JoinHostPort(host, port), &tls.Config{ServerName: host})
	default:
		if port == "" {
			port = "80"
		}
		return net.Dial("tcp", net.JoinHostPort(host, port))
	}
}

func mustHostname(rawURL string) string {
	u, _ := url.Parse(rawURL)
	return u.Hostname()
}
