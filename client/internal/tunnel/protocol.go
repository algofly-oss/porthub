// Package tunnel is a Go implementation of the rathole client protocol
// (https://github.com/rapiz1/rathole, Apache License 2.0, protocol v1 over the
// TCP transport). It is wire-compatible with the unmodified rathole server, so
// the PortHub server side and existing shell clients are unaffected.
//
// Messages are bincode 1 (little-endian, fixed-width integers): an enum is a
// u32 variant index followed by its fields; a [u8; 32] digest is 32 raw bytes.
package tunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const protocolVersion = 1

type digest = [32]byte

const (
	helloControl uint32 = 0 // Hello::ControlChannelHello(version, sha256(service) | nonce)
	helloData    uint32 = 1 // Hello::DataChannelHello(version, session key)

	ackOK              uint32 = 0
	ackServiceNotExist uint32 = 1
	ackAuthFailed      uint32 = 2

	cmdCreateDataChannel uint32 = 0 // ControlChannelCmd
	cmdHeartBeat         uint32 = 1

	cmdStartForwardTCP uint32 = 0 // DataChannelCmd
	cmdStartForwardUDP uint32 = 1
)

const helloSize = 4 + 1 + 32

func sum(parts ...[]byte) digest {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var d digest
	copy(d[:], h.Sum(nil))
	return d
}
func encodeHello(kind uint32, d digest) []byte {
	b := make([]byte, helloSize)
	binary.LittleEndian.PutUint32(b, kind)
	b[4] = protocolVersion
	copy(b[5:], d[:])
	return b
}
func readHello(r io.Reader) (uint32, digest, error) {
	var b [helloSize]byte
	var d digest
	if n, err := io.ReadFull(r, b[:]); err != nil {
		// An unknown service is answered with a bare 4-byte Ack, then EOF.
		if n == 4 && errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, d, AuthError{binary.LittleEndian.Uint32(b[:4])}
		}
		return 0, d, fmt.Errorf("read hello: %w", err)
	}
	kind := binary.LittleEndian.Uint32(b[:4])
	if kind > helloData {
		return 0, d, errors.New("malformed hello")
	}
	if b[4] != protocolVersion {
		return 0, d, fmt.Errorf("rathole protocol version mismatch: server %d, client %d", b[4], protocolVersion)
	}
	copy(d[:], b[5:])
	return kind, d, nil
}
func readU32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}
func encodeU32(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

type AuthError struct{ Ack uint32 }

func (e AuthError) Error() string {
	switch e.Ack {
	case ackServiceNotExist:
		return "service does not exist on the server"
	case ackAuthFailed:
		return "incorrect token"
	}
	return fmt.Sprintf("unexpected server acknowledgement %d", e.Ack)
}
