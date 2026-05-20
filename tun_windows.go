//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

const packetOffset = 0

type wgTun struct {
	d      tun.Device
	rbufs  [][]byte
	sizes  []int
	rIdx   int
	rCount int
}

func createTun(mtu int) (tunDev, string, error) {
	// Try fixed name first; fall back to a pid-suffixed name if busy.
	d, err := tun.CreateTUN("ttun", mtu)
	if err != nil {
		d, err = tun.CreateTUN(fmt.Sprintf("ttun%d", os.Getpid()), mtu)
		if err != nil {
			return nil, "", err
		}
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
	_ = v4peer
	ip4 := net.ParseIP(v4)
	if ip4 == nil {
		return fmt.Errorf("invalid v4: %s", v4)
	}
	ip6 := net.ParseIP(v6)
	if ip6 == nil {
		return fmt.Errorf("invalid v6: %s", v6)
	}
	mb4 := 32
	if n, err := strconv.Atoi(v4mask); err == nil {
		mb4 = n
	}
	ipNet := &net.IPNet{IP: ip4, Mask: net.CIDRMask(mb4, 32)}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mtuArgs := []string{"interface", "ip", "set", "subinterface", ifName, "mtu=" + strconv.Itoa(mtu)}
	if err := exec.CommandContext(ctx, "netsh", mtuArgs...).Run(); err != nil {
		return fmt.Errorf("netsh %v: %v", mtuArgs, err)
	}
	a4 := []string{
		"interface", "ip", "set", "address",
		"name=" + ifName,
		"source=static",
		"addr=" + ip4.String(),
		"mask=" + ipMaskStr(ipNet.Mask),
		"gateway=none",
	}
	if err := exec.CommandContext(ctx, "netsh", a4...).Run(); err != nil {
		return fmt.Errorf("netsh %v: %v", a4, err)
	}
	mtu6Args := []string{"interface", "ipv6", "set", "subinterface", ifName, "mtu=" + strconv.Itoa(mtu)}
	if err := exec.CommandContext(ctx, "netsh", mtu6Args...).Run(); err != nil {
		return fmt.Errorf("netsh %v: %v", mtu6Args, err)
	}
	a6 := []string{
		"interface", "ipv6", "set", "address",
		"interface=" + ifName,
		"address=" + ip6.String() + "/" + v6mask,
	}
	if err := exec.CommandContext(ctx, "netsh", a6...).Run(); err != nil {
		return fmt.Errorf("netsh %v: %v", a6, err)
	}
	return nil
}

func ipMaskStr(mask net.IPMask) string {
	if len(mask) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	}
	return net.IP(mask).String()
}
