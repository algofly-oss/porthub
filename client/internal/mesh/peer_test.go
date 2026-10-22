package mesh

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestDirectEncryptedPacketExchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ca, err := Certificate()
	if err != nil {
		t.Fatal(err)
	}
	cb, err := Certificate()
	if err != nil {
		t.Fatal(err)
	}
	fa, _ := Fingerprint(ca)
	fb, _ := Fingerprint(cb)
	ra, rb := make(chan []byte, 1), make(chan []byte, 1)
	a, err := New(ca, nil, true, func(b []byte) { ra <- append([]byte(nil), b...) })
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(cb, nil, true, func(b []byte) { rb <- append([]byte(nil), b...) })
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	offer, err := a.Offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := b.Answer(ctx, offer, fa)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Remote(answer, fb); err != nil {
		t.Fatal(err)
	}
	if err = a.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if err = b.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	packet := append([]byte{0x45}, bytes.Repeat([]byte{0x77}, 1199)...)
	if err = a.Send(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-rb:
		if !bytes.Equal(packet, got) {
			t.Fatal("packet corrupted")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err = b.Send(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ra:
		if !bytes.Equal(packet, got) {
			t.Fatal("reply corrupted")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if path, err := a.Path(); err != nil || path != "direct" {
		t.Fatalf("wanted direct peer path, got %q: %v", path, err)
	}
	if err = a.Send(make([]byte, MaxPacket+1)); err == nil {
		t.Fatal("oversized packet accepted")
	}
}
func TestMismatchedIdentityRejected(t *testing.T) {
	c, _ := Certificate()
	fp, _ := Fingerprint(c)
	p, err := New(c, nil, true, func([]byte) {})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s := Description{Type: "offer", SDP: "a=fingerprint:sha-256 " + strings.Repeat("AA:", 31) + "AA\r\n"}
	if p.Remote(s, fp) == nil {
		t.Fatal("untrusted certificate accepted")
	}
	s.SDP = "v=0\r\n"
	if p.Remote(s, fp) == nil {
		t.Fatal("missing fingerprint accepted")
	}
}
