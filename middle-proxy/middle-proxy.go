package main

import (
	"flag"
	"fmt"

	"inet.af/tcpproxy"
)

func main() {

	flagDestination := flag.String("destination", "192.168.74.128:8000", "address of destination server like 127.0.0.1:8000")
	flagAddr := flag.String("addr", "192.168.74.128:8001", "where to listen like 127.0.0.1:8001")

	flag.Parse()
	if *flagDestination == "" {
		flag.Usage()
		fmt.Println("empty socks server")
	}
	if *flagAddr == "" {
		flag.Usage()
		fmt.Println("empty addr - I do not know where to listen")
	}

	var p tcpproxy.Proxy
	p.AddRoute(*flagAddr, tcpproxy.To(*flagDestination))
	p.Run()
}
