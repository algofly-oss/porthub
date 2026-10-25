package mesh

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestTunnelThroughput measures one-way packet throughput between two peers
// on loopback: the CPU cost of the transport itself (skipped with -short).
func TestTunnelThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, _ := Certificate()
	cb, _ := Certificate()
	fa, _ := Fingerprint(ca)
	fb, _ := Fingerprint(cb)
	var received atomic.Int64
	a, _ := New(ca, nil, true, func([]byte) {})
	defer a.Close()
	b, _ := New(cb, nil, true, func(p []byte) { received.Add(int64(len(p))) })
	defer b.Close()
	offer, _ := a.Offer(ctx)
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
	packet := make([]byte, MaxPacket)
	packet[0] = 0x45
	start := time.Now()
	for time.Since(start) < 3*time.Second {
		if a.Send(packet) != nil {
			time.Sleep(20 * time.Microsecond)
		}
	}
	time.Sleep(200 * time.Millisecond)
	t.Logf("delivered %.0f Mbit/s", float64(received.Load())*8/time.Since(start).Seconds()/1e6)
}
