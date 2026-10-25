// Development-only Pion private-peer reference; never shipped in runtime images.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/algofly-oss/porthub/client/internal/mesh"
	"github.com/algofly-oss/porthub/client/internal/relay"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, err := mesh.Certificate()
	if err != nil {
		return err
	}
	cb, err := mesh.Certificate()
	if err != nil {
		return err
	}
	fa, err := mesh.Fingerprint(ca)
	if err != nil {
		return err
	}
	fb, err := mesh.Fingerprint(cb)
	if err != nil {
		return err
	}
	encode, decode := json.NewEncoder(os.Stdout), json.NewDecoder(io.LimitReader(os.Stdin, 65536))
	if err = encode.Encode(map[string]any{"fingerprints": []string{fa, fb}}); err != nil {
		return err
	}
	var input struct {
		RelayURL string             `json:"relay_url"`
		Servers  [][]mesh.ICEServer `json:"ice_servers"`
	}
	if err = decode.Decode(&input); err != nil {
		return err
	}
	trace("configuration received")
	if len(input.Servers) != 2 {
		return errors.New("two relay contexts required")
	}
	base := strings.TrimSuffix(input.RelayURL, relay.Path)
	base = strings.Replace(strings.Replace(base, "wss://", "https://", 1), "ws://", "http://", 1)
	credential := input.Servers[0][len(input.Servers[0])-1]
	if score, err := relay.Measure(ctx, base, credential.Username, credential.Credential); err != nil || score <= 0 {
		return errors.New("native relay route measurement failed")
	}
	trace("route measured")
	incoming := make(chan []byte, 128)
	a, err := mesh.New(ca, input.Servers[0], true, func(packet []byte) {
		select {
		case incoming <- append([]byte(nil), packet...):
		default:
		}
	}, mesh.WithRelay(tracedDialer{URL: input.RelayURL}), mesh.RelayOnly(), mesh.GatherOnce())
	if err != nil {
		return err
	}
	defer a.Close()
	var b *mesh.Peer
	b, err = mesh.New(cb, input.Servers[1], true, func(packet []byte) { _ = b.Send(packet) }, mesh.WithRelay(tracedDialer{URL: input.RelayURL}), mesh.RelayOnly(), mesh.GatherOnce())
	if err != nil {
		return err
	}
	defer b.Close()
	offer, err := a.Offer(ctx)
	if err != nil {
		return err
	}
	trace("offer gathered")
	answer, err := b.Answer(ctx, offer, fa)
	if err != nil {
		return err
	}
	trace("answer gathered")
	if err = a.Remote(answer, fb); err != nil {
		return err
	}
	if err = a.Wait(ctx); err != nil {
		return err
	}
	trace("offer connected")
	if err = b.Wait(ctx); err != nil {
		return err
	}
	trace("answer connected")
	pa, err := a.Path()
	if err != nil {
		return err
	}
	pb, err := b.Path()
	if err != nil {
		return err
	}
	if pa != "relay" || pb != "relay" {
		return errors.New("relay was bypassed")
	}
	for i := 0; i < 256; i++ {
		packet := bytes.Repeat([]byte{byte(i % 251)}, mesh.MaxPacket)
		packet[0] = 0x45
		if err = a.Send(packet); err != nil {
			return err
		}
		select {
		case result := <-incoming:
			if !bytes.Equal(result, packet) {
				return errors.New("packet integrity failed")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return encode.Encode(map[string]any{"packets": 256, "bytes": 256 * mesh.MaxPacket, "both_relay": true})
}
func trace(stage string) {
	if os.Getenv("PORTHUB_COMPAT_TRACE") == "1" {
		_, _ = io.WriteString(os.Stderr, "TURN reference: "+stage+"\n")
	}
}

type tracedDialer struct{ URL string }

func (d tracedDialer) Dial(network, address string) (net.Conn, error) {
	trace("relay dialing")
	connection, err := (relay.Dialer{URL: d.URL}).Dial(network, address)
	if err == nil {
		trace("relay connected")
	} else {
		trace("relay dial failed")
	}
	return connection, err
}
func main() {
	log.SetOutput(io.Discard)
	if run() != nil {
		_, _ = io.WriteString(os.Stderr, "legacy relay peer fixture failed\n")
		os.Exit(1)
	}
}
