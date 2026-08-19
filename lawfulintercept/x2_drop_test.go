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
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/omec-project/li/x1"
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

// TestADroppedUnitIsReportedAsALossAndNotAsUnreachability is the consumer half of the
// finding, asserted where the decision is made.
//
// A partial write costs one product unit only where the library's own resend of that unit
// does not land either — it resends it whole on the fresh connection, which recovers the
// ordinary case. What is left is a genuine loss to a destination that took the rest of the
// batch, and the library reports it as ErrUnitDropped precisely so it is not mistaken for
// unreachability: a healthy mediation function reported unreachable would have the watcher
// raise a fault about a working peer and retract it on the next send.
//
// This element then discarded the error and nudged the watcher, which sampled a destination
// it correctly considered reachable. So the loss the library correctly stopped mis-reporting
// as unreachability was reported nowhere at all — product missing from an agency's record
// with every channel that could have said so reporting normality.
//
// The transport that produces the error is tested where it lives (li/x2x3's partial-write
// suite, which drives a real socket). What this element does with it is this hook, and
// driving a real partial write to reach it would be asserting the other half twice while
// leaving this one's outcome to the machine's socket buffers.
func TestADroppedUnitIsReportedAsALossAndNotAsUnreachability(t *testing.T) {
	cert, key, ca, _ := loopbackPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	if err := Init(Config{
		NEID:     "smf-1",
		X1Listen: "127.0.0.1:0",
		MDF2:     "10.0.60.122:42069",
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: "admf-1",
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	sub := active.Load()
	if sub == nil {
		t.Fatal("interception did not start")
	}

	// A watcher over no destinations, so the nudge has somewhere to go and reports nothing
	// of its own: what is asserted here is what the hook says, not what the watcher samples.
	watcher := x1.NewDestinationWatcher(func() []x1.DestinationHealth { return nil }, sub.reporter, 0)

	// The error as the library returns it: wrapped, because a caller must match it with
	// errors.Is rather than by comparison.
	sub.reportDeliveryError(fmt.Errorf("%w: send to 10.0.60.122:42069", x2x3.ErrUnitDropped), watcher)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(admf.received(), "\n"), "x2DeliveryLost") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("an xIRI was dropped on the way to a reachable mediation function and reported by "+
		"nothing:\n%s", strings.Join(admf.received(), "\n"))
}

// And the other direction, which is what keeps the fix from turning every delivery failure
// into a product-loss report: an ordinary transport failure says the destination is not
// working, which is the watcher's to report at the scope that names it, not a loss of
// product this element can name.
func TestAnOrdinaryDeliveryFailureIsNotReportedAsALoss(t *testing.T) {
	cert, key, ca, _ := loopbackPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	if err := Init(Config{
		NEID:     "smf-1",
		X1Listen: "127.0.0.1:0",
		MDF2:     "10.0.60.122:42069",
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: "admf-1",
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	sub := active.Load()
	if sub == nil {
		t.Fatal("interception did not start")
	}
	watcher := x1.NewDestinationWatcher(func() []x1.DestinationHealth { return nil }, sub.reporter, 0)

	sub.reportDeliveryError(errors.New("dial tcp 10.0.60.122:42069: connection refused"), watcher)

	// Nothing to wait for, so give the asynchronous path a moment to be wrong in.
	time.Sleep(200 * time.Millisecond)
	if joined := strings.Join(admf.received(), "\n"); strings.Contains(joined, "x2DeliveryLost") {
		t.Errorf("a connection failure was reported as lost product:\n%s", joined)
	}
}
