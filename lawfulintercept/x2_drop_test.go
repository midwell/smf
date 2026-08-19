// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/li/x2x3"
)

// loopbackPKI is liPKI with an IP SAN, so a stub mediation function on the loopback
// can present the same certificate and be *verified* rather than merely trusted. The
// distinction is the whole point of this test: a peer that fails the handshake is
// unreachable, and what has to be reproduced here is a peer that is reachable.
func loopbackPKI(t *testing.T) (certPath, keyPath, caPath string, pair tls.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mdf2"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	caPath = filepath.Join(dir, "ca.crt")
	for path, body := range map[string][]byte{certPath: certPEM, keyPath: keyPEM, caPath: certPEM} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	pair, pairErr := tls.X509KeyPair(certPEM, keyPEM)
	if pairErr != nil {
		t.Fatal(pairErr)
	}

	return certPath, keyPath, caPath, pair
}

// slowMDF2 completes the TLS handshake and then never reads. That is precisely the
// condition a reachability probe deliberately does not answer: the destination is up,
// the connection is established, and product is being offered faster than it is taken.
func slowMDF2(t *testing.T, pair tls.Certificate) string {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup

	held := make(chan struct{})
	t.Cleanup(func() { close(held) })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck // test
				<-held
			}()
		}
	}()

	return ln.Addr().String()
}

// TestProductDroppedByAFullQueueIsReported is the combination that made this silent,
// and it is driven through Init rather than through a pool a test builds itself,
// because what was wrong was the wiring: the hook was passed nil, with a comment
// asserting the worker's unreachability report covered these drops. It does not.
// AsyncSender.Unreachable excludes queue saturation deliberately — a full queue at one
// instant is a burst the buffer exists to absorb — and says in the same paragraph that
// the drops themselves are reported as they happen. At the UPF they were. Here nothing
// reported them, so a reachable-but-slow MDF2 lost xIRI while every channel that could
// have said so reported normality.
func TestProductDroppedByAFullQueueIsReported(t *testing.T) {
	cert, key, ca, pair := loopbackPKI(t)
	admf := newADMFStub(t)
	mdf2 := slowMDF2(t, pair)
	t.Cleanup(func() { active.Store(nil) })

	if err := Init(Config{
		NEID:     "smf-1",
		X1Listen: "127.0.0.1:0",
		MDF2:     mdf2,
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: "admf-1",
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	sub := active.Load()
	if sub == nil {
		t.Fatal("interception did not start")
	}
	s := sub.senderFor(mdf2)

	// Comfortably past the queue's 1024, offered faster than a peer that never reads
	// can take them.
	pdu := &x2x3.PDU{Type: x2x3.PDUTypeX2, Payload: make([]byte, 512)}
	for range 8000 {
		//nolint:errcheck // enqueueing cannot fail in a way this test acts on
		_ = s.Send(pdu)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(admf.received(), "\n"), "x2DeliveryLost") {
			// The other half, and the reason this was invisible: the destination is
			// still described as healthy, because by every measure it is.
			if r, ok := s.(x2x3.Reachability); ok && r.Unreachable() {
				t.Error("the destination reports unreachable; this test no longer reproduces " +
					"the reachable-but-slow case it exists for")
			}

			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("product was dropped for want of queue space and nothing was reported:\n%s",
		strings.Join(admf.received(), "\n"))
}

// halfOpenMDF2 accepts connections, reads a bounded number of bytes on the first and
// then stops reading while holding it open, so a write large enough to fill the socket
// buffer trips the client's write deadline part-way through. The second connection reads
// everything, which is what the client's single reconnect lands on.
//
// That is the whole of the condition: **the destination is reachable** — it completed a
// TLS handshake with a verified certificate and it accepts the retry — and one product
// unit of what was offered is lost, because a partially written unit cannot be resumed
// on a fresh stream without the peer taking its tail for the head of the next one.
func halfOpenMDF2(t *testing.T, pair tls.Certificate, stallAfter int) string {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup

	held := make(chan struct{})
	t.Cleanup(func() { close(held) })

	var mu sync.Mutex
	accepted := 0

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			mu.Lock()
			accepted++
			stall := accepted == 1
			mu.Unlock()

			go func() {
				defer conn.Close() //nolint:errcheck // test

				buf := make([]byte, 4096)
				read := 0
				for {
					if stall && read >= stallAfter {
						<-held

						return
					}
					if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
						return
					}
					n, err := conn.Read(buf)
					read += n
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	return ln.Addr().String()
}

// TestAPartialWriteToAReachableMDFIsReportedAsALoss is the second half of the same
// finding as TestProductDroppedByAFullQueueIsReported, and it was reported by even less.
//
// A partial write costs one xIRI. The library correctly refuses to call that
// unreachability — a healthy mediation function must not be reported as unreachable over
// one truncated write, and doing so would have the watcher raise a fault about a working
// destination and retract it on the next send — so it returns ErrUnitDropped instead.
// This element's hook then discarded the error and nudged the watcher, which sampled a
// destination it correctly considered reachable and reported normality. The loss was
// reported by nothing at all: product missing from an agency's record with every channel
// that could have said so agreeing that nothing was wrong.
//
// Both halves are asserted here, because either alone is satisfiable by the wrong fix:
// the loss is reported, **and** the destination is still reachable.
func TestAPartialWriteToAReachableMDFIsReportedAsALoss(t *testing.T) {
	cert, key, ca, pair := loopbackPKI(t)
	admf := newADMFStub(t)
	// 64 KiB read and then no more: the client's own 5s write deadline is what ends the
	// stalled write, so this test costs that once.
	mdf2 := halfOpenMDF2(t, pair, 64*1024)
	t.Cleanup(func() { active.Store(nil) })

	if err := Init(Config{
		NEID:     "smf-1",
		X1Listen: "127.0.0.1:0",
		MDF2:     mdf2,
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: "admf-1",
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	sub := active.Load()
	if sub == nil {
		t.Fatal("interception did not start")
	}
	s := sub.senderFor(mdf2)

	// One unit, far larger than any socket buffer, so the write cannot complete and the
	// unit cannot be resumed. A single PDU is the sharpest form: there are no boundaries
	// to resume at, so exactly one unit is lost and nothing else is in question.
	//nolint:errcheck // the loss is the contract; what is asserted is that it is reported
	_ = s.Send(&x2x3.PDU{
		Type:          x2x3.PDUTypeX2,
		PayloadFormat: x2x3.PayloadFormat3GPP33128,
		Payload:       make([]byte, 2*1024*1024),
	})

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(admf.received(), "\n"), "x2DeliveryLost") {
			// The other half, and the reason this was invisible: the destination is
			// reachable, by every measure including its own.
			if r, ok := s.(x2x3.Reachability); ok && r.Unreachable() {
				t.Error("the destination reports unreachable after a dropped unit; this test no " +
					"longer reproduces the reachable-MDF case it exists for, and the watcher " +
					"would now raise a fault about a working mediation function")
			}

			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("an xIRI was partially written to a reachable mediation function, dropped, and "+
		"reported by nothing:\n%s", strings.Join(admf.received(), "\n"))
}
