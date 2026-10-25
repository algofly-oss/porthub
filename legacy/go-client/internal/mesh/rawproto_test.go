package mesh

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/ice/v4"
)

func pinned(pin [32]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 || sha256.Sum256(raw[0]) != pin {
			return errors.New("pin mismatch")
		}
		return nil
	}
}

func TestRawDTLSOverICEThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mk := func() *ice.Agent {
		a, err := ice.NewAgent(&ice.AgentConfig{NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4}, IncludeLoopback: true})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a, b := mk(), mk()
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	wire := func(from, to *ice.Agent) {
		from.OnCandidate(func(c ice.Candidate) {
			if c != nil {
				to.AddRemoteCandidate(c)
			}
		})
	}
	wire(a, b)
	wire(b, a)
	ua, pa, _ := a.GetLocalUserCredentials()
	ub, pb, _ := b.GetLocalUserCredentials()
	a.GatherCandidates()
	b.GatherCandidates()
	ca, _ := selfsign.GenerateSelfSigned()
	cb, _ := selfsign.GenerateSelfSigned()
	pinA, pinB := sha256.Sum256(ca.Certificate[0]), sha256.Sum256(cb.Certificate[0])
	var ia, ib net.Conn
	wg.Add(2)
	go func() {
		defer wg.Done()
		c, err := a.Dial(ctx, ub, pb)
		if err != nil {
			t.Error(err)
		}
		ia = c
	}()
	go func() {
		defer wg.Done()
		c, err := b.Accept(ctx, ua, pa)
		if err != nil {
			t.Error(err)
		}
		ib = c
	}()
	wg.Wait()
	var da, db *dtls.Conn
	wg.Add(2)
	go func() {
		defer wg.Done()
		c, err := dtls.Client(dtlsnet.PacketConnFromConn(ia), ia.RemoteAddr(), &dtls.Config{Certificates: []tls.Certificate{ca}, InsecureSkipVerify: true, VerifyPeerCertificate: pinned(pinB), ExtendedMasterSecret: dtls.RequireExtendedMasterSecret, CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}})
		if err == nil {
			err = c.HandshakeContext(ctx)
		}
		if err != nil {
			t.Error(err)
		}
		da = c
	}()
	go func() {
		defer wg.Done()
		c, err := dtls.Server(dtlsnet.PacketConnFromConn(ib), ib.RemoteAddr(), &dtls.Config{Certificates: []tls.Certificate{cb}, ClientAuth: dtls.RequireAnyClientCert, VerifyPeerCertificate: pinned(pinA), ExtendedMasterSecret: dtls.RequireExtendedMasterSecret, CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}})
		if err == nil {
			err = c.HandshakeContext(ctx)
		}
		if err != nil {
			t.Error(err)
		}
		db = c
	}()
	wg.Wait()
	if t.Failed() {
		return
	}
	var received int64
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := db.Read(buf)
			if err != nil {
				return
			}
			atomic.AddInt64(&received, int64(n))
		}
	}()
	packet := make([]byte, 1400)
	start := time.Now()
	var sent int64
	for time.Since(start) < 3*time.Second {
		if _, err := da.Write(packet); err != nil {
			t.Fatal(err)
		}
		sent += int64(len(packet))
	}
	time.Sleep(200 * time.Millisecond)
	el := time.Since(start).Seconds()
	t.Logf("raw DTLS over ICE: sent %.0f Mbit/s, received %.0f Mbit/s", float64(sent)*8/el/1e6, float64(atomic.LoadInt64(&received))*8/el/1e6)
}
