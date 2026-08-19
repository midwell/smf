// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/li/store"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/lisequence"
	"github.com/wmnsk/go-pfcp/ie"
)

// duplicatingSession is a session whose forwarding FARs are marked as a sent LI
// modification leaves them: `RULE_CREATE`, because
// BuildPfcpSessionModificationRequest clears `RULE_UPDATE` on everything it encodes.
//
// That is the state the retry has to work from, and the reason a re-derivation cannot: the
// marker that selects these FARs is gone, and the SMF-side `Dupl` bit already equals what
// the tasking implies, so `applyCC` finds nothing changed.
func duplicatingSession(t *testing.T) *smfctx.SMContext {
	t.Helper()

	sc := pooledSession(t, "imsi-262019876543210", 1)
	node := smfctx.NewDataPathNode()
	node.UPF = &smfctx.UPF{NodeID: upfNode("10.0.1.5")}
	node.UpLinkTunnel.PDR["default"] = &smfctx.PDR{
		FAR: &smfctx.FAR{
			ApplyAction: smfctx.ApplyAction{Forw: true, Dupl: true},
			State:       smfctx.RULE_CREATE,
		},
	}
	sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
		1: &smfctx.DataPath{FirstDPNode: node, IsDefaultPath: true, Activated: true},
	}}
	sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{}
	// Allocated the way the session path allocates it, which is what registers the session
	// in the SEID index. The answer to a modification carries the SEID and nothing else, so
	// a session not in that index is one the retry cannot find — and the test would then
	// pass against a retry that never ran.
	sc.AllocateLocalSEIDForDataPath(sc.Tunnel.DataPathPool[1])
	sc.PFCPContext["10.0.1.5"].RemoteSEID = 0x2632898145f4d191

	return sc
}

// outcomeFixture is a subsystem whose PFCP modifications are counted rather than sent, with
// a real reporter pointed at a stub ADMF.
func outcomeFixture(t *testing.T) (*subsystem, *admfStub, func() int) {
	t.Helper()

	admf := newADMFStub(t)
	sub := &subsystem{
		store:    store.New(),
		neID:     "smf-1",
		ids:      x2x3.NewIdentity("smf-1", smfInterceptionPoint),
		reporter: x1.NewReporter(admf.srv.URL, "admf-1", "smf-1", nil),
	}
	waitForScans(t, sub)

	var (
		mu   sync.Mutex
		sent int
	)
	restore := sessionModifier
	sessionModifier = func(*smfctx.SMContext) error {
		mu.Lock()
		defer mu.Unlock()
		sent++

		return nil
	}
	t.Cleanup(func() { sessionModifier = restore })

	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	return sub, admf, func() int {
		mu.Lock()
		defer mu.Unlock()

		return sent
	}
}

// TestARefusedDuplicationIsRetriedAndThenReported is the whole of *the SMF acts on the
// answer to its own PFCP modifications*.
//
// The `lisequence` guard exists so an LI-initiated response cannot complete a subscriber's
// concurrent procedure, which is right and required. What it also did was `return` without
// reading the Cause — so a refused activation was never retried, and could not be: the send
// itself cleared the `RULE_UPDATE` marker `ModifySessionForLI` selects on, and `applyCC`
// will not set it again because the SMF-side `Dupl` bit already matches the tasking. The
// element was left holding a task it reports as intercepting and a datapath that declined
// it, with nothing to re-send and nothing reported.
//
// Two properties. The refusal is retried, which requires the marker to be re-established.
// And a datapath that keeps refusing is reported rather than asked forever, because it is
// refusing for a reason this element cannot fix.
func TestARefusedDuplicationIsRetriedAndThenReported(t *testing.T) {
	sub, admf, sent := outcomeFixture(t)
	sc := duplicatingSession(t)

	// The session has to be findable by the SEID the answer carries, which is how the
	// response handler correlates it.
	req := lisequence.Request{
		SEID:        sc.PFCPContext["10.0.1.5"].LocalSEID,
		NodeID:      "10.0.1.5",
		Duplicating: true,
	}

	// The datapath refuses.
	ModificationAnswered(req, ie.CauseRequestRejected, true)

	if n := sent(); n != 1 {
		t.Fatalf("a refused duplication produced %d re-sends, want 1: the element recorded the "+
			"change as made and had nothing left to re-send, so the interception never started", n)
	}
	// The marker is back, which is the half a re-derivation cannot supply.
	sc.SMLock.Lock()
	marked := 0
	forEachForwardingFAR(sc, func(far *smfctx.FAR) {
		if far.State == smfctx.RULE_UPDATE {
			marked++
		}
	})
	sc.SMLock.Unlock()
	if marked == 0 {
		t.Error("the re-send carried nothing: the FAR state the send cleared was not " +
			"re-established, so ModifySessionForLI selects no FAR at all")
	}

	// It keeps refusing. Past the bound the element stops asking and tells the ADMF, because
	// a retry loop against a datapath that will not apply it has no exit.
	for range maxModificationAttempts {
		// Each answer leaves the FARs marked again, as the send would.
		sc.SMLock.Lock()
		forEachForwardingFAR(sc, func(far *smfctx.FAR) { far.State = smfctx.RULE_CREATE })
		sc.SMLock.Unlock()
		ModificationAnswered(req, ie.CauseRequestRejected, true)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(admf.received(), "\n"), "duplicationRefused") {
			// And it stopped asking.
			before := sent()
			ModificationAnswered(req, ie.CauseRequestRejected, true)
			if after := sent(); after > before+1 {
				t.Errorf("the element sent %d more modifications after giving up", after-before)
			}
			_ = sub

			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("a datapath that kept refusing an acknowledged interception was reported to "+
		"nobody:\n%s", strings.Join(admf.received(), "\n"))
}

// TestARefusedWithdrawalIsNotBelieved is the other direction, and the one whose silence is
// worse. A refused activation is an interception that is not running; a refused withdrawal
// is content still being duplicated under authority that has gone, which nothing downstream
// can tell from content that is authorised.
func TestARefusedWithdrawalIsNotBelieved(t *testing.T) {
	_, admf, sent := outcomeFixture(t)
	sc := duplicatingSession(t)

	// The withdrawal: the FARs were sent with Dupl cleared.
	sc.SMLock.Lock()
	forEachForwardingFAR(sc, func(far *smfctx.FAR) {
		far.ApplyAction.Dupl = false
		far.State = smfctx.RULE_CREATE
	})
	sc.SMLock.Unlock()

	req := lisequence.Request{
		SEID:        sc.PFCPContext["10.0.1.5"].LocalSEID,
		NodeID:      "10.0.1.5",
		Duplicating: false,
	}

	ModificationAnswered(req, ie.CauseRequestRejected, true)

	if n := sent(); n != 1 {
		t.Fatalf("a refused withdrawal produced %d re-sends, want 1: the element believes "+
			"duplication is off while the datapath is still copying a subject's traffic", n)
	}

	for range maxModificationAttempts {
		sc.SMLock.Lock()
		forEachForwardingFAR(sc, func(far *smfctx.FAR) { far.State = smfctx.RULE_CREATE })
		sc.SMLock.Unlock()
		ModificationAnswered(req, ie.CauseRequestRejected, true)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if joined := strings.Join(admf.received(), "\n"); strings.Contains(joined, "duplicationRefused") {
			if !strings.Contains(joined, "withdrawn") && !strings.Contains(joined, "authority") {
				t.Errorf("the report does not distinguish a refused withdrawal from a refused "+
					"activation; they need opposite actions:\n%s", joined)
			}

			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("a refused withdrawal was reported to nobody:\n%s", strings.Join(admf.received(), "\n"))
}

// TestAnUnansweredModificationIsTreatedAsRefused: silence is not a lesser case. A refusal
// says the datapath declined; silence says this element does not know — and it recorded the
// duplication as applied before it sent. Over-applying duplication is visible to the CC-POI
// as content it can attribute; under-applying it is silent, so the ambiguous case resolves
// toward retry.
func TestAnUnansweredModificationIsTreatedAsRefused(t *testing.T) {
	_, _, sent := outcomeFixture(t)
	sc := duplicatingSession(t)

	req := lisequence.Request{
		SEID:        sc.PFCPContext["10.0.1.5"].LocalSEID,
		NodeID:      "10.0.1.5",
		Duplicating: true,
	}

	// answered=false: no Cause could be read, or none arrived.
	ModificationAnswered(req, 0, false)

	if n := sent(); n != 1 {
		t.Errorf("an unanswered duplication produced %d re-sends, want 1", n)
	}
}

// TestAnAcceptedModificationIsLeftAlone keeps the fix from becoming a re-send loop on the
// ordinary path: the datapath took it, so there is nothing to do.
func TestAnAcceptedModificationIsLeftAlone(t *testing.T) {
	_, admf, sent := outcomeFixture(t)
	sc := duplicatingSession(t)

	req := lisequence.Request{
		SEID:        sc.PFCPContext["10.0.1.5"].LocalSEID,
		NodeID:      "10.0.1.5",
		Duplicating: true,
	}

	ModificationAnswered(req, ie.CauseRequestAccepted, true)

	if n := sent(); n != 0 {
		t.Errorf("an accepted modification produced %d re-sends, want 0", n)
	}
	time.Sleep(100 * time.Millisecond)
	if joined := strings.Join(admf.received(), "\n"); strings.Contains(joined, "duplicationRefused") {
		t.Errorf("an accepted modification was reported as refused:\n%s", joined)
	}
}
