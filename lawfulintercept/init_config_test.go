// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// liPKI writes a throwaway LI certificate, key and trust anchor, and returns their
// paths. Init loads credentials before it reads anything else, so a test that wants to
// reach the configuration checks has to get past mtls.Load first.
func liPKI(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "smf-1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	caPath = filepath.Join(dir, "ca.crt")

	write := func(path, blockType string, der []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(certPath, "CERTIFICATE", der)
	write(keyPath, "EC PRIVATE KEY", keyDER)
	write(caPath, "CERTIFICATE", der)

	return certPath, keyPath, caPath
}

// admfStub accepts NE issue reports and records their bodies.
type admfStub struct {
	srv *httptest.Server

	mu     sync.Mutex
	bodies []string
}

func newADMFStub(t *testing.T) *admfStub {
	t.Helper()

	a := &admfStub{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test handler

		a.mu.Lock()
		a.bodies = append(a.bodies, string(body))
		a.mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(a.srv.Close)

	return a
}

func (a *admfStub) received() []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]string(nil), a.bodies...)
}

// TestUnreadableKeepaliveWindowStopsInterceptionAndTellsTheADMF is the property that
// makes this refusal better than the one it replaces.
//
// The window used to be read *before* Init, where there was no fault channel to report
// on — so the refusal had to be made by returning from the network function's own
// start-up, and nothing could tell the provisioning function why. Read inside Init, the
// refusal costs interception and nothing else, and the one party who needs to know that
// this element is not intercepting is told: no interrogation reveals it, since an
// element holding no tasking answers every query successfully and looks exactly like one
// nobody has tasked.
func TestUnreadableKeepaliveWindowStopsInterceptionAndTellsTheADMF(t *testing.T) {
	cert, key, ca := liPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	err := Init(Config{
		NEID:     "smf-1",
		X1Listen: "127.0.0.1:0",
		MDF2:     "10.0.60.122:42069",
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: "admf-1",
		// The typo this exists for: seconds meant, no unit given.
		KeepaliveTimeout: "30",
	})
	if err == nil {
		t.Fatal("Init accepted a keepalive window it cannot read; a deployment that asked " +
			"for the fail-safe would hold tasking nothing will ever reclaim")
	}

	if sub := active.Load(); sub != nil {
		t.Error("interception was started despite the refusal")
	}

	reports := admf.received()
	if len(reports) == 0 {
		t.Fatal("nothing was reported to the ADMF; an element that is not intercepting " +
			"because it could not read its own configuration is in a state no interrogation reveals")
	}
	joined := strings.Join(reports, "\n")
	if !strings.Contains(joined, "invalidConfig") {
		t.Errorf("the report does not carry invalidConfig:\n%s", joined)
	}
	// NE-level, and naming no target or warrant — there are none, and the rule holds
	// regardless.
	if strings.Contains(joined, "30") && strings.Contains(joined, "keepaliveTimeout=") {
		t.Errorf("the report echoes the operator's value back on the LI channel:\n%s", joined)
	}
}

// TestAStatedEmptyWindowIsHonoured keeps the other reading available. An operator who
// writes nothing has said the fail-safe is off, which is a choice — not a value this
// element could not read — and interception starts.
func TestAStatedEmptyWindowIsHonoured(t *testing.T) {
	cert, key, ca := liPKI(t)
	t.Cleanup(func() { active.Store(nil) })

	if err := Init(Config{
		NEID:     "smf-1",
		X1Listen: "127.0.0.1:0",
		MDF2:     "10.0.60.122:42069",
		Cert:     cert, Key: key, CACert: ca,
		KeepaliveTimeout: "",
	}); err != nil {
		t.Fatalf("Init refused an empty keepalive window: %v", err)
	}
	if active.Load() == nil {
		t.Error("interception did not start with the fail-safe deliberately off")
	}
}

// TestASubFloorKeepaliveWindowStopsInterceptionRatherThanTheProcess is the second path
// on which an LI configuration mistake still cost the network function.
//
// "1ns" is a well-formed Go duration, so it passes the chart's regex — ns is a unit —
// and it is positive, so it passed this element's own test. The fail-safe window is then
// halved to produce the watchdog's tick interval, and integer division reaches zero:
// time.NewTicker panics, on a goroutine, and the SMF goes down. An element that
// terminates under an LI misconfiguration when one without interception configured does
// not is distinguishable to anybody who can see whether it is running — the class of
// leak this capability exists to prevent, arrived at from the configuration file.
//
// The policy is the one already applied to an unreadable window: interception does not
// start, the ADMF is told, and the network function serves.
func TestASubFloorKeepaliveWindowStopsInterceptionRatherThanTheProcess(t *testing.T) {
	cert, key, ca := liPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	err := Init(Config{
		NEID:     "smf-1",
		X1Listen: "127.0.0.1:0",
		MDF2:     "10.0.60.122:42069",
		Cert:     cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: "admf-1",
		KeepaliveTimeout: "1ns",
	})
	if err == nil {
		t.Fatal("Init accepted a fail-safe window shorter than the watchdog can measure")
	}
	if sub := active.Load(); sub != nil {
		t.Error("interception was started despite the refusal")
	}
	if joined := strings.Join(admf.received(), "\n"); !strings.Contains(joined, "invalidConfig") {
		t.Errorf("the refusal was not reported to the ADMF:\n%s", joined)
	}
}

// TestNoX1ListenAddressStopsInterceptionAndTellsTheADMF covers the configuration mistake that
// produced a *working* element nobody could provision.
//
// `Listen(ctx, "tcp", "")` does not fail. It binds every interface at an OS-selected ephemeral
// port, so with `x1Listen` absent — misspelled, or templated from a value that rendered
// empty — interception started, `active` was set, and the element waited for tasking on a port
// the ADMF has no way to learn. Every X1 request it should have received went to a closed port
// on the configured one instead, and from outside, an element holding no tasking is
// indistinguishable from one nobody has tasked: it answers interrogation successfully and reports
// nothing wrong. The mistake only surfaces when a warrant that was supposed to be running turns
// out never to have arrived.
//
// The policy is the one the other configuration refusals take: interception does not start, the
// ADMF is told over the channel that exists for exactly this, and the network function serves
// traffic — an element that terminates over its LI configuration is distinguishable from one that
// has none.
func TestNoX1ListenAddressStopsInterceptionAndTellsTheADMF(t *testing.T) {
	cert, key, ca := liPKI(t)
	admf := newADMFStub(t)
	t.Cleanup(func() { active.Store(nil) })

	err := Init(Config{
		NEID: "smf-1",
		// x1Listen absent. This is the whole fixture.
		MDF2: "10.0.60.122:42069",
		Cert: cert, Key: key, CACert: ca,
		AdmfURL: admf.srv.URL, AdmfID: "admf-1",
	})
	if !errors.Is(err, errNoX1Listen) {
		t.Fatalf("Init returned %v, want errNoX1Listen — an empty address binds successfully on "+
			"an unpredictable port, so nothing further down will ever report it", err)
	}

	if active.Load() != nil {
		t.Error("interception was started, which is what makes an unprovisionable element look " +
			"healthy")
	}

	joined := strings.Join(admf.received(), "\n")
	if !strings.Contains(joined, "invalidConfig") {
		t.Errorf("the refusal was not reported to the ADMF, which is the one party that needs to "+
			"know this element cannot be provisioned:\n%s", joined)
	}
}
