//go:build linux

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

const packetOffset = 16

type wgTun struct {
	d      tun.Device
	rbufs  [][]byte
	sizes  []int
	rIdx   int
	rCount int
}

func createTun(mtu int) (tunDev, string, error) {
	var d tun.Device
	var err error
	var devName string
	for i := 0; i < 32; i++ {
		name := fmt.Sprintf("ttun%d", i)
		d, err = tun.CreateTUN(name, mtu)
		if err == nil {
			devName, err = d.Name()
			if err == nil {
				break
			}
			d.Close()
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("no free ttunN device: %w", err)
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
	_ = v4peer
	if net.ParseIP(v4) == nil {
		return fmt.Errorf("invalid v4: %s", v4)
	}
	if net.ParseIP(v6) == nil {
		return fmt.Errorf("invalid v6: %s", v6)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "ip", "link", "set", ifName, "mtu", strconv.Itoa(mtu), "up").Run(); err != nil {
		return fmt.Errorf("ip link: %v", err)
	}
	if err := exec.CommandContext(ctx, "ip", "addr", "add", v4+"/"+v4mask, "dev", ifName).Run(); err != nil {
		return fmt.Errorf("ip addr v4: %v", err)
	}
	if err := exec.CommandContext(ctx, "ip", "-6", "addr", "add", v6+"/"+v6mask, "dev", ifName).Run(); err != nil {
		return fmt.Errorf("ip addr v6: %v", err)
	}
	return nil
}
