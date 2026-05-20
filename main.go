package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const (
	defaultPort = "20203"
	serverV4    = "10.1.1.1"
	clientV4    = "10.1.1.2"
	v4Mask      = "30"
	serverV6    = "fc11::1"
	clientV6    = "fc11::2"
	v6Mask      = "126"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  ttun server [flags]
  ttun client [flags]

flags:
  -m chacha20-poly1305|aes-256-gcm   cipher (default chacha20-poly1305)
  -k <psk>              preshared key (required)
  -l <addr>             (server) listen, default :20203
  -s <host:port>        (client) server address
  -mtu <n>              MTU, default 1280

tunnel addresses are fixed (dual-stack):
  server  10.1.1.1/30   fc11::1/126
  client  10.1.1.2/30   fc11::2/126`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	if cmd != "server" && cmd != "client" {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cipher := fs.String("m", "chacha20-poly1305", "cipher: chacha20-poly1305|aes-256-gcm")
	psk := fs.String("k", "", "preshared key")
	listen := fs.String("l", ":"+defaultPort, "listen address")
	server := fs.String("s", "", "server host:port")
	mtu := fs.Int("mtu", 1280, "MTU")
	_ = fs.Parse(os.Args[2:])

	if *psk == "" {
		fmt.Fprintln(os.Stderr, "missing -k <psk>")
		os.Exit(2)
	}
	var v4, v4peer, v6 string
	if cmd == "server" {
		v4, v4peer, v6 = serverV4, clientV4, serverV6
	} else {
		v4, v4peer, v6 = clientV4, serverV4, clientV6
	}
	cf, err := newCipher(*cipher, []byte(*psk))
	if err != nil {
		log.Fatalf("cipher: %v", err)
	}
	log.Printf("ttun %s cipher=%s", cmd, cf.name)

	switch cmd {
	case "server":
		runServer(*listen, cf, v4, v4peer, v6, *mtu)
	case "client":
		if *server == "" {
			fmt.Fprintln(os.Stderr, "missing -s host:port")
			os.Exit(2)
		}
		runClient(*server, cf, v4, v4peer, v6, *mtu)
	}
}

type session struct {
	dev  tunDev
	mu   sync.RWMutex
	conn *aeadConn
}

func (s *session) tunReadLoop() {
	buf := make([]byte, 65536)
	for {
		n, err := s.dev.ReadPacket(buf)
		if err != nil {
			log.Printf("tun read: %v", err)
			return
		}
		if n == 0 {
			continue
		}
		s.mu.RLock()
		c := s.conn
		s.mu.RUnlock()
		if c == nil {
			continue
		}
		if err := c.writeFrame(buf[:n]); err != nil {
			log.Printf("net write: %v", err)
		}
	}
}

func (s *session) run(c *aeadConn) {
	s.mu.Lock()
	s.conn = c
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.conn = nil
		s.mu.Unlock()
		c.Close()
	}()
	for {
		pt, err := c.readFrame()
		if err != nil {
			return
		}
		if _, err := s.dev.WritePacket(pt); err != nil {
			log.Printf("tun write: %v", err)
			return
		}
	}
}

func openTun(v4, v4peer, v6 string, mtu int) tunDev {
	dev, devName, err := createTun(mtu)
	if err != nil {
		log.Fatalf("tun create: %v", err)
	}
	if err := setupAddr(devName, v4, v4Mask, v4peer, v6, v6Mask, mtu); err != nil {
		dev.Close()
		log.Fatalf("tun setup: %v", err)
	}
	log.Printf("tun %s up: %s/%s %s/%s mtu=%d", devName, v4, v4Mask, v6, v6Mask, mtu)
	return dev
}

func tuneTCP(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.SetNoDelay(true)
		_ = t.SetKeepAlive(true)
		_ = t.SetKeepAlivePeriod(15 * time.Second)
	}
}

func runServer(addr string, cf cipherFactory, v4, v4peer, v6 string, mtu int) {
	dev := openTun(v4, v4peer, v6, mtu)
	defer dev.Close()
	sess := &session{dev: dev}
	go sess.tunReadLoop()

	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer l.Close()
	log.Printf("listen %s", addr)

	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		tuneTCP(c)
		log.Printf("peer %s connected; handshaking", c.RemoteAddr())
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		ac, err := handshake(c, cf, false)
		if err != nil {
			log.Printf("handshake from %s rejected: %v", c.RemoteAddr(), err)
			c.Close()
			continue
		}
		_ = c.SetDeadline(time.Time{})
		log.Printf("peer %s authenticated; pinned 1:1, listener idle", c.RemoteAddr())
		sess.run(ac)
		log.Printf("peer disconnected; accepting new connections")
	}
}

func runClient(server string, cf cipherFactory, v4, v4peer, v6 string, mtu int) {
	dev := openTun(v4, v4peer, v6, mtu)
	defer dev.Close()
	sess := &session{dev: dev}
	go sess.tunReadLoop()

	backoff := time.Second
	for {
		c, err := net.DialTimeout("tcp", server, 10*time.Second)
		if err != nil {
			log.Printf("dial %s: %v", server, err)
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		tuneTCP(c)
		log.Printf("connected to %s; handshaking", server)
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		ac, err := handshake(c, cf, true)
		if err != nil {
			log.Printf("handshake: %v", err)
			c.Close()
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		_ = c.SetDeadline(time.Time{})
		log.Printf("authenticated")
		start := time.Now()
		sess.run(ac)
		if time.Since(start) > 60*time.Second {
			backoff = time.Second
		}
		log.Printf("disconnected, reconnecting in %s", backoff)
		time.Sleep(backoff)
	}
}
