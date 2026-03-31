// measure connects to an HTTP or HTTPS target and uses 0trace to display the
// network path, like a stateful traceroute.
//
// Usage:
//
//	# probe along an HTTP/HTTPS connection (root required)
//	sudo ./measure https://example.com
//	sudo ./measure https://example.com:8443
//
//	# probe along an existing 5-tuple (root required)
//	sudo ./measure -src 192.168.1.6:54321 -dst 93.184.216.34:443
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/augustin-laouar/zerotrace"
)

func main() {
	srcFlag := flag.String("src", "", "source address of an existing connection, e.g. 192.168.1.6:54321")
	dstFlag := flag.String("dst", "", "destination address of an existing connection, e.g. 93.184.216.34:443")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] [http(s)://host[:port]]\n\nflags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Mode 1: explicit 5-tuple via -src / -dst flags.
	if *srcFlag != "" || *dstFlag != "" {
		if *srcFlag == "" || *dstFlag == "" {
			fmt.Fprintln(os.Stderr, "error: -src and -dst must be used together")
			os.Exit(1)
		}
		src, err := net.ResolveTCPAddr("tcp4", *srcFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid -src: %v\n", err)
			os.Exit(1)
		}
		dst, err := net.ResolveTCPAddr("tcp4", *dstFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid -dst: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("traceroute %s -> %s\n", src, dst)
		printHops(zerotrace.TracerouteAddr(src, dst))
		return
	}

	// Mode 2: open an HTTP/HTTPS connection ourselves.
	rawURL := "http://example.com"
	if flag.NArg() > 0 {
		rawURL = flag.Arg(0)
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

	// Send a GET request so NAT mappings stay alive during the probing window.
	host := mustHostname(rawURL)
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", host)

	fmt.Printf("traceroute to %s\n", rawURL)
	printHops(zerotrace.Traceroute(conn))
}

func printHops(hops []zerotrace.Hop, err error) {
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
