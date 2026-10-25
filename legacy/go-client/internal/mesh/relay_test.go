package mesh

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/algofly-oss/porthub/client/internal/relay"
	"github.com/pion/turn/v5"
)

const secret = "relay-test-secret-0123456789abcdefghij"

func relayPair(t *testing.T, credential func() (string, string)) (*Peer, *Peer, chan []byte, func()) {
	t.Helper()
	server, err := relay.NewServer(secret, 256)
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(server)
	endpoint := "ws" + strings.TrimPrefix(web.URL, "http") + relay.Path
	user, pass := credential()
	servers := []ICEServer{{URLs: []string{"turn:relay.porthub.invalid:443?transport=tcp"}, Username: user, Credential: pass}}
	options := []Option{RelayOnly(), WithRelay(relay.Dialer{URL: endpoint})}
	ca, _ := Certificate()
	cb, _ := Certificate()
	received := make(chan []byte, 4)
	a, err := New(ca, servers, false, func([]byte) {}, options...)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(cb, servers, false, func(p []byte) { received <- append([]byte(nil), p...) }, options...)
	if err != nil {
		t.Fatal(err)
	}
	fa, _ := Fingerprint(ca)
	fb, _ := Fingerprint(cb)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	offer, err := a.Offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := b.Answer(ctx, offer, fa)
	if err == nil {
		err = a.Remote(answer, fb)
	}
	if err != nil {
		t.Fatal(err)
	}
	return a, b, received, func() { a.Close(); b.Close(); web.Close(); server.Close() }
}

func TestRelayCarriesEncryptedPackets(t *testing.T) {
	a, b, received, done := relayPair(t, func() (string, string) {
		u, p, _ := turn.GenerateLongTermTURNRESTCredentials(secret, "workspace:peer", time.Hour)
		return u, p
	})
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := a.Wait(ctx); err != nil {
		t.Fatalf("relay connection: %v", err)
	}
	if err := b.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if path, _ := a.Path(); path != "relay" {
		t.Fatalf("path %q, want relay", path)
	}
	packet := append([]byte{0x45}, bytes.Repeat([]byte{7}, MaxPacket-1)...)
	if err := a.Send(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, packet) {
			t.Fatal("packet corrupted through relay")
		}
	case <-ctx.Done():
		t.Fatal("no packet through relay")
	}
}

func TestRelayRejectsForgedAndExpiredCredentials(t *testing.T) {
	for name, credential := range map[string]func() (string, string){
		"forged": func() (string, string) { return "9999999999:workspace:peer", "not-the-signature" },
		"expired": func() (string, string) {
			u, p, _ := turn.GenerateLongTermTURNRESTCredentials(secret, "w:p", -time.Minute)
			return u, p
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, _, _, done := relayPair(t, credential)
			defer done()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if a.Wait(ctx) == nil {
				t.Fatal("relay accepted invalid credentials")
			}
		})
	}
}
