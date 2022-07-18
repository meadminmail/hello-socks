package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

// 超时时间设置
const (
	defaultTimeout           = 180 * time.Second
	defaultPrometheusAddress = ":9200"
	connDeadline             = 60 * time.Second
)

func main() {
	flagLocalAddr := flag.String("addr", "0.0.0.0:8080", "address to listen to like 0.0.0.0:8080")

	flagRemoteAddr := flag.String("server", "192.168.74.128:8001", "address of the tls socks server like 0.0.0.0:8000")
	flagInsecureSkipVerify := flag.Bool("insecure-skip-verify", false, "allow insecure skipping of peer verification, when talking to the server")
	flag.Parse()

	// 本地端口监听器
	localSocksListener, err := net.Listen("tcp", *flagLocalAddr)

	if err != nil {
		fmt.Printf("启动服务失败失败, 错误：%v", err)
		return
	}

	defer silentClose(localSocksListener)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: *flagInsecureSkipVerify,
	}
	if tlsConfig.InsecureSkipVerify {
		fmt.Println("Running without verification of the tls server - this is dangerous")
	}

	// 创建上下文
	ctx := ctxCancelOnOsSignal()

	var connID uint64
	for {
		localConn, err := localSocksListener.Accept()
		if err != nil {
			fmt.Printf("%d", err)
		}
		connID++
		go serve(ctx, localConn, *flagRemoteAddr, tlsConfig, connID)
	}

}

/** socks5处理函数 */
func serve(ctx context.Context, localConn net.Conn, remoteAddress string, tlsConfig *tls.Config, connID uint64) {
	start := time.Now()
	fmt.Printf("%s\n", localConn.LocalAddr())

	// 关闭连接
	defer silentClose(localConn)

	remoteConn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: defaultTimeout,
	}, "tcp", remoteAddress, tlsConfig)

	if err != nil {
		fmt.Printf("could not reach remote tls server, 错误：%v", err)
		return
	}

	defer silentClose(remoteConn)

	p := &proxy{
		wait: make(chan struct{}),
	}

	deadline := start.Add(connDeadline)
	localConn.SetDeadline(deadline)
	remoteConn.SetDeadline(deadline)

	go p.pipe(ctx, remoteConn, localConn, isLocalConnection)
	go p.pipe(ctx, localConn, remoteConn, isLocalNotConnection)

	<-p.wait
	fmt.Printf("request served bytes_sent: %d, bytes_received: %d\n", &p.sentBytes, &p.receivedBytes)
}

func silentClose(c io.Closer) {
	if c != nil {
		_ = c.Close()
	}
}

func ctxCancelOnOsSignal() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		defer func() {
			signal.Stop(c)
			cancel()
		}()
		select {
		case c2 := <-c:
			fmt.Printf("Received interrupt signal and cancelling context: signal:%s", c2.String())
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx
}

type proxy struct {
	sentBytes     uint64
	receivedBytes uint64
	wait          chan struct{}
}

const (
	isLocalConnection    = true
	isLocalNotConnection = false
)

func (p *proxy) pipe(ctx context.Context, dist io.Writer, src io.Reader, isLocal bool) {
	buff := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			fmt.Printf("context error, 错误：%v", ctx.Err())
			return
		}
		n, err := src.Read(buff[:])
		if err != nil {
			fmt.Printf("读错误：%v", err)
			return
		}

		n, err = dist.Write(buff[:n])
		if err != nil {
			fmt.Printf("写错误：%v", err)
			return
		}

		if isLocal {
			atomic.AddUint64(&p.sentBytes, uint64(n))
		} else {
			atomic.AddUint64(&p.receivedBytes, uint64(n))
		}
	}
}
