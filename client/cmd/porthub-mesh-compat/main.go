// Development-only compatibility fixture for the Rust transport tests.
// It is never bundled in the native images or agent distribution.
package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"time"

	"github.com/algofly-oss/porthub/client/internal/mesh"
	"github.com/algofly-oss/porthub/client/internal/relay"
)

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cert, err := mesh.Certificate()
	if err != nil {
		return err
	}
	fingerprint, err := mesh.Fingerprint(cert)
	if err != nil {
		return err
	}
	encode, decode := json.NewEncoder(os.Stdout), json.NewDecoder(io.LimitReader(os.Stdin, 131072))
	if err = encode.Encode(map[string]string{"fingerprint": fingerprint}); err != nil {
		return err
	}
	var start struct {
		Role        string           `json:"role"`
		Fingerprint string           `json:"fingerprint"`
		RelayURL    string           `json:"relay_url"`
		Servers     []mesh.ICEServer `json:"ice_servers"`
	}
	if err = decode.Decode(&start); err != nil {
		return err
	}
	packets := make(chan []byte, 128)
	options := []mesh.Option{mesh.GatherOnce()}
	if start.RelayURL != "" {
		options = append(options, mesh.WithRelay(relay.Dialer{URL: start.RelayURL}), mesh.RelayOnly())
	}
	peer, err := mesh.New(cert, start.Servers, true, func(packet []byte) {
		select {
		case packets <- append([]byte(nil), packet...):
		default:
		}
	}, options...)
	if err != nil {
		return err
	}
	defer peer.Close()
	if start.Role == "offer" {
		offer, err := peer.Offer(ctx)
		if err != nil {
			return err
		}
		if err = encode.Encode(offer); err != nil {
			return err
		}
		var answer mesh.Description
		if err = decode.Decode(&answer); err != nil {
			return err
		}
		if err = peer.Remote(answer, start.Fingerprint); err != nil {
			return err
		}
	} else {
		var offer mesh.Description
		if err = decode.Decode(&offer); err != nil {
			return err
		}
		answer, err := peer.Answer(ctx, offer, start.Fingerprint)
		if err != nil {
			return err
		}
		if err = encode.Encode(answer); err != nil {
			return err
		}
	}
	if err = peer.Wait(ctx); err != nil {
		return err
	}
	if err = encode.Encode(map[string]bool{"ready": true}); err != nil {
		return err
	}
	go func() { var done any; _ = decode.Decode(&done); cancel() }()
	for {
		select {
		case packet := <-packets:
			if err = peer.Send(packet); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func main() {
	log.SetOutput(io.Discard)
	if run() != nil {
		_, _ = io.WriteString(os.Stderr, "legacy peer compatibility fixture failed\n")
		os.Exit(1)
	}
}
