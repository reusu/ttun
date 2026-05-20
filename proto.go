package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	hsNonceLen = 16
	authMagic  = "TTUN/v1\x00"
	// maxFrame: largest plaintext per frame. 2-byte length header holds
	// ciphertext length (= plaintext + 16 tag), so plaintext max = 65535 - 16.
	maxFrame = 65519
)

type cipherFactory struct {
	name string
	key  []byte
	new  func(key []byte) (cipher.AEAD, error)
}

func newCipher(name string, psk []byte) (cipherFactory, error) {
	h, _ := blake2s.New256(nil)
	h.Write([]byte("ttun/psk/v1"))
	h.Write(psk)
	k := h.Sum(nil)
	switch name {
	case "chacha20-poly1305":
		return cipherFactory{name: "chacha20-poly1305", key: k, new: chacha20poly1305.New}, nil
	case "aes-256-gcm":
		mk := func(k []byte) (cipher.AEAD, error) {
			b, err := aes.NewCipher(k)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(b)
		}
		return cipherFactory{name: "aes-256-gcm", key: k, new: mk}, nil
	default:
		return cipherFactory{}, fmt.Errorf("unknown cipher %q (want chacha20-poly1305 or aes-256-gcm)", name)
	}
}

func deriveSessionKey(k, nc, ns []byte) []byte {
	h, _ := blake2s.New256(nil)
	h.Write([]byte("ttun/sk/v1"))
	h.Write(k)
	h.Write(nc)
	h.Write(ns)
	return h.Sum(nil)
}

type aeadConn struct {
	net.Conn
	tx, rx       cipher.AEAD
	txDir, rxDir byte
	txCtr, rxCtr uint64
	wbuf, rbuf   []byte
	wmu, rmu     sync.Mutex
}

func putNonce(out []byte, dir byte, ctr uint64) {
	out[0] = dir
	out[1] = 0
	out[2] = 0
	out[3] = 0
	binary.BigEndian.PutUint64(out[4:], ctr)
}

func handshake(c net.Conn, f cipherFactory, isClient bool) (*aeadConn, error) {
	mine := make([]byte, hsNonceLen)
	if _, err := rand.Read(mine); err != nil {
		return nil, err
	}
	theirs := make([]byte, hsNonceLen)
	if isClient {
		if _, err := c.Write(mine); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(c, theirs); err != nil {
			return nil, err
		}
	} else {
		if _, err := io.ReadFull(c, theirs); err != nil {
			return nil, err
		}
		if _, err := c.Write(mine); err != nil {
			return nil, err
		}
	}

	var nc, ns []byte
	if isClient {
		nc, ns = mine, theirs
	} else {
		nc, ns = theirs, mine
	}
	sk := deriveSessionKey(f.key, nc, ns)
	tx, err := f.new(sk)
	if err != nil {
		return nil, err
	}
	rx, err := f.new(sk)
	if err != nil {
		return nil, err
	}
	ac := &aeadConn{Conn: c, tx: tx, rx: rx}
	if isClient {
		ac.txDir, ac.rxDir = 0, 1
	} else {
		ac.txDir, ac.rxDir = 1, 0
	}

	// PSK proof: each side AEAD-encrypts the magic; tag verification on the
	// other side fails iff PSK differs.
	if isClient {
		if err := ac.writeFrame([]byte(authMagic)); err != nil {
			return nil, err
		}
		got, err := ac.readFrame()
		if err != nil {
			return nil, fmt.Errorf("psk verify (wrong key or cipher mismatch): %w", err)
		}
		if string(got) != authMagic {
			return nil, errors.New("bad server magic")
		}
	} else {
		got, err := ac.readFrame()
		if err != nil {
			return nil, fmt.Errorf("psk verify (wrong key or cipher mismatch): %w", err)
		}
		if string(got) != authMagic {
			return nil, errors.New("bad client magic")
		}
		if err := ac.writeFrame([]byte(authMagic)); err != nil {
			return nil, err
		}
	}
	return ac, nil
}

func (c *aeadConn) writeFrame(p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if len(p) > maxFrame {
		return fmt.Errorf("frame too large: %d", len(p))
	}
	var nonce [12]byte
	putNonce(nonce[:], c.txDir, c.txCtr)
	c.txCtr++
	c.wbuf = c.wbuf[:0]
	c.wbuf = append(c.wbuf, 0, 0)
	c.wbuf = c.tx.Seal(c.wbuf, nonce[:], p, nil)
	binary.BigEndian.PutUint16(c.wbuf[:2], uint16(len(c.wbuf)-2))
	_, err := c.Conn.Write(c.wbuf)
	return err
}

func (c *aeadConn) readFrame() ([]byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var hdr [2]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	tag := c.rx.Overhead()
	if n < tag || n > maxFrame+tag {
		return nil, fmt.Errorf("invalid frame size %d", n)
	}
	if cap(c.rbuf) < n {
		c.rbuf = make([]byte, n)
	} else {
		c.rbuf = c.rbuf[:n]
	}
	if _, err := io.ReadFull(c.Conn, c.rbuf); err != nil {
		return nil, err
	}
	var nonce [12]byte
	putNonce(nonce[:], c.rxDir, c.rxCtr)
	c.rxCtr++
	return c.rx.Open(c.rbuf[:0], nonce[:], c.rbuf, nil)
}
