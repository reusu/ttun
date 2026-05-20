package main

type tunDev interface {
	ReadPacket(p []byte) (int, error)
	WritePacket(p []byte) (int, error)
	Close() error
}
