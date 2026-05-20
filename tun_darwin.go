//go:build darwin

package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

const packetOffset = 4

type wgTun struct {
	d      tun.Device
	rbufs  [][]byte
	sizes  []int
	rIdx   int
	rCount int
}

func createTun(mtu int) (tunDev, string, error) {
	// "utun" lets the darwin kernel auto-allocate utunN.
	d, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, "", err
	}
	devName, err := d.Name()
	if err != nil {
		d.Close()
		return nil, "", err
	}
	bs := d.BatchSize()
	if bs < 1 {
		bs = 1
	}
	rbufs := make([][]byte, bs)
	for i := range rbufs {
		rbufs[i] = make([]byte, packetOffset+65536)
	}
	return &wgTun{d: d, rbufs: rbufs, sizes: make([]int, bs)}, devName, nil
}

func (t *wgTun) ReadPacket(p []byte) (int, error) {
	for {
		for t.rIdx < t.rCount {
			i := t.rIdx
			t.rIdx++
			if t.sizes[i] > 0 {
				return copy(p, t.rbufs[i][packetOffset:packetOffset+t.sizes[i]]), nil
			}
		}
		clear(t.sizes)
		n, err := t.d.Read(t.rbufs, t.sizes, packetOffset)
		if err != nil {
			return 0, err
		}
		t.rIdx, t.rCount = 0, n
	}
}

func (t *wgTun) WritePacket(p []byte) (int, error) {
	buf := make([]byte, packetOffset+len(p))
	copy(buf[packetOffset:], p)
	if _, err := t.d.Write([][]byte{buf}, packetOffset); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *wgTun) Close() error { return t.d.Close() }

func setupAddr(ifName, v4, v4mask, v4peer, v6, v6mask string, mtu int) error {
	if net.ParseIP(v4) == nil {
		return fmt.Errorf("invalid v4: %s", v4)
	}
	if net.ParseIP(v6) == nil {
		return fmt.Errorf("invalid v6: %s", v6)
	}
	if v4peer == "" {
		v4peer = v4
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a4 := []string{ifName, "inet", v4 + "/" + v4mask, v4peer, "mtu", strconv.Itoa(mtu), "up"}
	if err := exec.CommandContext(ctx, "ifconfig", a4...).Run(); err != nil {
		return fmt.Errorf("ifconfig %v: %v", a4, err)
	}
	a6 := []string{ifName, "inet6", v6 + "/" + v6mask, "mtu", strconv.Itoa(mtu), "up"}
	if err := exec.CommandContext(ctx, "ifconfig", a6...).Run(); err != nil {
		return fmt.Errorf("ifconfig %v: %v", a6, err)
	}
	return nil
}
