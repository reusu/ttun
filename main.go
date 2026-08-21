package main

import (
	"context"
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
  -mptcp[=false]        force Multipath TCP on/off (Linux only; falls back
                        to plain TCP elsewhere or if the peer lacks MPTCP).
                        Omit the flag to keep the Go/system default.

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
	mptcp := fs.Bool("mptcp", false, "force Multipath TCP on/off (Linux); omit to keep system default")
	_ = fs.Parse(os.Args[2:])

	// Only override the Go/system default when -mptcp was actually given, so
	// that an unset flag keeps GODEBUG=multipathtcp / platform behaviour.
	mo := mptcpOpt{use: *mptcp}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "mptcp" {
			mo.set = true
		}
	})

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
	log.Printf("ttun %s cipher=%s mptcp=%s", cmd, cf.name, mo)

	switch cmd {
	case "server":
		runServer(*listen, cf, v4, v4peer, v6, *mtu, mo)
	case "client":
		if *server == "" {
			fmt.Fprintln(os.Stderr, "missing -s host:port")
			os.Exit(2)
		}
		runClient(*server, cf, v4, v4peer, v6, *mtu, mo)
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

// mptcpOpt carries the -mptcp flag. set is false when the flag was omitted,
// in which case we leave the decision to Go / GODEBUG / the OS.
type mptcpOpt struct {
	set bool
	use bool
}

func (m mptcpOpt) String() string {
	if !m.set {
		return "default"
	}
	if m.use {
		return "on"
	}
	return "off"
}

func (m mptcpOpt) listenConfig() *net.ListenConfig {
	lc := &net.ListenConfig{}
	if m.set {
		lc.SetMultipathTCP(m.use)
	}
	return lc
}

func (m mptcpOpt) dialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if m.set {
		d.SetMultipathTCP(m.use)
	}
	return d
}

// connKind reports whether the established connection actually negotiated
// MPTCP; a forced -mptcp still falls back to plain TCP if the peer or a
// middlebox does not support it.
func connKind(c net.Conn) string {
	t, ok := c.(*net.TCPConn)
	if !ok {
		return "tcp"
	}
	on, err := t.MultipathTCP()
	if err != nil || !on {
		return "tcp"
	}
	return "mptcp"
}

func runServer(addr string, cf cipherFactory, v4, v4peer, v6 string, mtu int, mo mptcpOpt) {
	dev := openTun(v4, v4peer, v6, mtu)
	defer dev.Close()
	sess := &session{dev: dev}
	go sess.tunReadLoop()

	l, err := mo.listenConfig().Listen(context.Background(), "tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer l.Close()
	log.Printf("listen %s (mptcp=%s)", addr, mo)

	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		tuneTCP(c)
		log.Printf("peer %s connected over %s; handshaking", c.RemoteAddr(), connKind(c))
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

func runClient(server string, cf cipherFactory, v4, v4peer, v6 string, mtu int, mo mptcpOpt) {
	dev := openTun(v4, v4peer, v6, mtu)
	defer dev.Close()
	sess := &session{dev: dev}
	go sess.tunReadLoop()

	backoff := time.Second
	for {
		c, err := mo.dialer(10*time.Second).Dial("tcp", server)
		if err != nil {
			log.Printf("dial %s: %v", server, err)
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		tuneTCP(c)
		log.Printf("connected to %s over %s; handshaking", server, connKind(c))
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
