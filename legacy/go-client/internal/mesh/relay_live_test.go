package mesh

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algofly-oss/porthub/client/internal/relay"
)

// TestLiveRelay checks a deployed relay end to end. Skipped unless
// PORTHUB_RELAY_TEST_URL/_USER/_PASS are set (short-lived credentials).
func TestLiveRelay(t *testing.T) {
	endpoint, user, pass := os.Getenv("PORTHUB_RELAY_TEST_URL"), os.Getenv("PORTHUB_RELAY_TEST_USER"), os.Getenv("PORTHUB_RELAY_TEST_PASS")
	if endpoint == "" {
		t.Skip("no live relay configured")
	}
	servers := []ICEServer{{URLs: []string{"turn:relay.porthub.invalid:443?transport=tcp"}, Username: user, Credential: pass}}
	options := []Option{RelayOnly(), WithRelay(relay.Dialer{URL: endpoint})}
	ca, _ := Certificate()
	cb, _ := Certificate()
	var received atomic.Int64
	a, err := New(ca, servers, false, func([]byte) {}, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(cb, servers, false, func(p []byte) { received.Add(int64(len(p))) }, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	fa, _ := Fingerprint(ca)
	fb, _ := Fingerprint(cb)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	offer, err := a.Offer(ctx)
	if err != nil {
		t.Fatalf("offer (gathering) after %v: %v", time.Since(start), err)
	}
	t.Logf("offer gathered in %v", time.Since(start))
	answer, err := b.Answer(ctx, offer, fa)
	if err == nil {
		err = a.Remote(answer, fb)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Wait(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Logf("connected via relay in %v", time.Since(start))
	b.Wait(ctx)
	packet := make([]byte, MaxPacket)
	packet[0] = 0x45
	sendStart, sent, refused := time.Now(), 0, 0
	for time.Since(sendStart) < 5*time.Second {
		if a.Send(packet) != nil {
			refused++
			time.Sleep(200 * time.Microsecond)
			continue
		}
		sent += len(packet)
	}
	time.Sleep(time.Second)
	secs := time.Since(sendStart).Seconds()
	t.Logf("offered %.1f Mbit/s, delivered %.1f Mbit/s through the relay (%d sends refused while congested)", float64(sent)*8/secs/1e6, float64(received.Load())*8/secs/1e6, refused)
}
