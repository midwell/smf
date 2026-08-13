// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/omec-project/li/iri"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
	"github.com/omec-project/openapi/v2/models"
	smfctx "github.com/omec-project/smf/context"
)

// captureSender records the xIRI PDUs delivered, standing in for the X2 client
// so tests can assert per-warrant delivery isolation.
type captureSender struct{ pdus []*x2x3.PDU }

func (c *captureSender) Send(p *x2x3.PDU) error {
	c.pdus = append(c.pdus, p)
	return nil
}

// targetSM is a fully-identified PDU-session context used across the tests.
func targetSM() *smfctx.SMContext {
	sd := "010203"
	return &smfctx.SMContext{
		Supi:                   "imsi-262019876543210",
		Pei:                    "imeisv-3534250000000151",
		Gpsi:                   "msisdn-4915123456789",
		Dnn:                    "internet",
		PDUSessionID:           5,
		SelectedPDUSessionType: 1, // IPv4
		Snssai:                 &models.Snssai{Sst: 1, Sd: &sd},
	}
}

func TestTargetsOf(t *testing.T) {
	got := targetsOf(targetSM())
	want := map[types.TargetIdentifierType]string{
		types.TargetSUPI: "262019876543210",
		types.TargetPEI:  "3534250000000151",
		types.TargetGPSI: "4915123456789",
	}
	if len(got) != len(want) {
		t.Fatalf("targetsOf returned %d ids, want %d: %+v", len(got), len(want), got)
	}
	for _, id := range got {
		if want[id.Type] != id.Value {
			t.Errorf("identifier %s = %q, want %q", id.Type, id.Value, want[id.Type])
		}
	}
	// An unmappable/absent identifier is not emitted.
	if ids := targetsOf(&smfctx.SMContext{Supi: "suci-0-262-01-..."}); len(ids) != 0 {
		t.Errorf("unmappable SUPI produced identifiers: %+v", ids)
	}
}

func TestEstablishmentMapping(t *testing.T) {
	est := smfEstablishment(targetSM())
	if supi, ok := est.SUPI.(iri.IMSI); !ok || supi != "262019876543210" {
		t.Errorf("SUPI = %#v", est.SUPI)
	}
	if pei, ok := est.PEI.(iri.IMEISV); !ok || pei != "3534250000000151" {
		t.Errorf("PEI = %#v", est.PEI)
	}
	if est.PDUSessionID != 5 || est.PDUSessionType != iri.PDUSessionTypeIPv4 {
		t.Errorf("id=%d type=%d", est.PDUSessionID, est.PDUSessionType)
	}
	if est.DNN != "internet" || est.RequestType != iri.SMRequestInitial {
		t.Errorf("dnn=%q req=%d", est.DNN, est.RequestType)
	}
	if est.SNSSAI.SliceServiceType != 1 || !bytes.Equal(est.SNSSAI.SliceDifferentiator, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("snssai = %+v", est.SNSSAI)
	}
}

func TestModificationAndReleaseMapping(t *testing.T) {
	mod := smfModification(targetSM())
	if mod.RequestType != iri.SMRequestModification || mod.PDUSessionID != 5 {
		t.Errorf("modification req=%d id=%d", mod.RequestType, mod.PDUSessionID)
	}
	rel := smfRelease(targetSM())
	if supi, ok := rel.SUPI.(iri.IMSI); !ok || supi != "262019876543210" || rel.PDUSessionID != 5 {
		t.Errorf("release supi=%#v id=%d", rel.SUPI, rel.PDUSessionID)
	}
}

func TestSnssai(t *testing.T) {
	// nil S-NSSAI → zero value.
	if s := snssai(&smfctx.SMContext{}); s.SliceServiceType != 0 || s.SliceDifferentiator != nil {
		t.Errorf("nil snssai = %+v, want zero", s)
	}
	// SST only (no SD).
	if s := snssai(&smfctx.SMContext{Snssai: &models.Snssai{Sst: 2}}); s.SliceServiceType != 2 || s.SliceDifferentiator != nil {
		t.Errorf("sst-only = %+v", s)
	}
	// SST + SD.
	sd := "0a0b0c"
	s := snssai(&smfctx.SMContext{Snssai: &models.Snssai{Sst: 1, Sd: &sd}})
	if s.SliceServiceType != 1 || !bytes.Equal(s.SliceDifferentiator, []byte{0x0a, 0x0b, 0x0c}) {
		t.Errorf("sst+sd = %+v", s)
	}
}

func TestServingUPFTEIDNilTunnel(t *testing.T) {
	// No tunnel yet → a zero F-TEID (best-effort), never a panic.
	if f := servingUPFTEID(&smfctx.SMContext{}); f.TEID != 0 || f.IPv4Address != nil || f.IPv6Address != nil {
		t.Errorf("nil-tunnel F-TEID = %+v, want zero", f)
	}
}

func TestCorrelationOfNilTunnel(t *testing.T) {
	// No PFCP session yet → a zero correlation ID (best-effort), never a panic.
	// The populated value (serving UPF F-SEID, big-endian, matching the UPF's X3)
	// is exercised end-to-end by the datapath integration test.
	if corr := correlationOf(&smfctx.SMContext{}); corr != ([8]byte{}) {
		t.Errorf("nil-tunnel correlation = % x, want zero", corr)
	}
	if seid := servingUPFSEID(&smfctx.SMContext{}); seid != 0 {
		t.Errorf("nil-tunnel serving UPF SEID = %d, want 0", seid)
	}
}

func TestParseXID(t *testing.T) {
	x := parseXID("50b93d1e-1b53-4d63-aacb-e4d99811bc0b")
	if x[0] != 0x50 || x[15] != 0x0b {
		t.Errorf("parseXID = % x", x)
	}
	if got := parseXID("not-a-uuid"); got != ([16]byte{}) {
		t.Errorf("bad XID = % x, want zero", got)
	}
}

// ccSession builds a minimal one-node PDU session whose default uplink PDR
// points at far, so ApplyCCTrigger has a forwarding FAR to act on.
func ccSession(far *smfctx.FAR) *smfctx.SMContext {
	node := smfctx.NewDataPathNode()
	node.UpLinkTunnel.PDR["default"] = &smfctx.PDR{FAR: far}
	return &smfctx.SMContext{
		Supi:   "imsi-262019876543210",
		Tunnel: &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{1: &smfctx.DataPath{FirstDPNode: node}}},
	}
}

// activateWith installs sub with a store holding task, and cleans up after.
func activateWith(t *testing.T, task types.InterceptTask) {
	t.Helper()
	st := store.New()
	if !st.Activate(task) {
		t.Fatalf("failed to activate test task %+v", task)
	}
	active.Store(&subsystem{store: st})
	t.Cleanup(func() { active.Store(nil) })
}

func TestApplyCCTriggerSetsDuplication(t *testing.T) {
	activateWith(t, types.InterceptTask{
		XID:      "task-cc",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI, types.ProductCC},
		State:    types.TaskActive,
	})

	far := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}}
	ApplyCCTrigger(ccSession(far))

	if !far.ApplyAction.Dupl {
		t.Fatal("CC-tasked session: DUPL not set on forwarding FAR")
	}
	if far.DuplicatingParameters == nil ||
		far.DuplicatingParameters.DestinationInterface.InterfaceValue != smfctx.DestinationInterfaceLIFunction {
		t.Errorf("DuplicatingParameters = %+v, want LI Function", far.DuplicatingParameters)
	}
}

func TestApplyCCTriggerClearsWhenNotCCTasked(t *testing.T) {
	// An IRI-only task must not trigger CC duplication, and must clear a FAR that
	// was previously duplicating.
	activateWith(t, types.InterceptTask{
		XID:      "task-iri",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	})

	far := &smfctx.FAR{
		ApplyAction:           smfctx.ApplyAction{Forw: true, Dupl: true},
		DuplicatingParameters: &smfctx.DuplicatingParameters{},
	}
	ApplyCCTrigger(ccSession(far))

	if far.ApplyAction.Dupl || far.DuplicatingParameters != nil {
		t.Errorf("IRI-only task must clear DUPL: dupl=%v params=%+v", far.ApplyAction.Dupl, far.DuplicatingParameters)
	}
}

func TestApplyCCTriggerSkipsNonForwardingFAR(t *testing.T) {
	activateWith(t, types.InterceptTask{
		XID:      "task-cc",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	})

	// A drop/buffer FAR (not forwarding) must never be marked for duplication.
	far := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Drop: true}}
	ApplyCCTrigger(ccSession(far))
	if far.ApplyAction.Dupl {
		t.Error("non-forwarding FAR must not be duplicated")
	}
}

// TestApplyCCTriggerMarksInstalledFARForUpdate: when the trigger flips
// DUPL on an already-installed FAR (RULE_CREATE) — e.g. SendPFCPRules re-invoked
// for an established session on a ULCL add / HO path-switch — it must mark the FAR
// RULE_UPDATE, or the modification builder skips it and the flip never reaches the
// UPF. An establishment FAR (RULE_INITIAL) must be left as-is (sent as Create).
func TestApplyCCTriggerMarksInstalledFARForUpdate(t *testing.T) {
	activateWith(t, types.InterceptTask{
		XID:      "task-cc",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	})

	installed := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}, State: smfctx.RULE_CREATE}
	ApplyCCTrigger(ccSession(installed))
	if !installed.ApplyAction.Dupl {
		t.Fatal("installed FAR: DUPL not set")
	}
	if installed.State != smfctx.RULE_UPDATE {
		t.Errorf("installed FAR State = %v, want RULE_UPDATE so the flip is sent", installed.State)
	}

	fresh := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}, State: smfctx.RULE_INITIAL}
	ApplyCCTrigger(ccSession(fresh))
	if fresh.State != smfctx.RULE_INITIAL {
		t.Errorf("establishment FAR State = %v, want RULE_INITIAL (sent as Create FAR)", fresh.State)
	}
}

// TestApplyCCTriggerRecoversAfterFARReactivation. Several SMF paths
// reconfigure a FAR by replacing its whole ApplyAction — the downlink FAR becoming
// a forwarding FAR once the RAN tunnel is known, a data-notification reactivating
// the uplink FAR, a ULCL path activation — and each of those assignments sets
// Dupl false.
//
// Two consequences, both silent. A downlink FAR is not a forwarding FAR at
// establishment, so the trigger skips it and the interception carries uplink only
// until something re-evaluates. And on a session already tasked, the same
// assignment switches duplication back off. The trigger is authoritative over
// DUPL, so calling it after any such reconfiguration restores the correct state;
// this pins that it actually does.
func TestApplyCCTriggerRecoversAfterFARReactivation(t *testing.T) {
	activateWith(t, types.InterceptTask{
		XID:      "task-cc",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	})

	// A downlink FAR as created at establishment: buffering, not forwarding.
	far := &smfctx.FAR{
		ApplyAction: smfctx.ApplyAction{Buff: true, Nocp: true},
		State:       smfctx.RULE_INITIAL,
	}
	sc := ccSession(far)

	ApplyCCTrigger(sc)
	if far.ApplyAction.Dupl {
		t.Error("a buffering FAR must not be duplicated")
	}

	// The RAN tunnel arrives and the FAR becomes forwarding, the assignment
	// clearing Dupl as the real code does.
	far.ApplyAction = smfctx.ApplyAction{Forw: true}
	far.State = smfctx.RULE_UPDATE

	ApplyCCTrigger(sc)
	if !far.ApplyAction.Dupl {
		t.Fatal("downlink FAR: DUPL not applied once it became forwarding — the MDF would receive uplink only")
	}
	if far.DuplicatingParameters == nil {
		t.Error("downlink FAR: Duplicating Parameters missing")
	}

	// And on an already-duplicating FAR, a reactivation that clears Dupl must be
	// recovered rather than left off.
	far.ApplyAction = smfContextApplyActionForwardOnly()
	ApplyCCTrigger(sc)
	if !far.ApplyAction.Dupl {
		t.Error("duplication was not restored after the FAR was reactivated")
	}
}

// smfContextApplyActionForwardOnly is the shape the SMF assigns when it
// reactivates forwarding: everything else, including Dupl, reset to false.
func smfContextApplyActionForwardOnly() smfctx.ApplyAction {
	return smfctx.ApplyAction{Forw: true}
}

// TestReportEstablishmentEmitsOnce covers that guard. The record is now emitted
// from the PFCP establishment-response handler, which runs once per UPF, so a
// session spanning several UPFs would otherwise produce one record per response.
func TestReportEstablishmentEmitsOnce(t *testing.T) {
	cap := &captureSender{}
	st := store.New()
	st.Activate(types.InterceptTask{
		XID:      "task-iri",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	})
	active.Store(&subsystem{store: st, senderFor: func(string) sender { return cap }, mdf2: configuredMDF2, iriCtx: iri.NewContext(), neID: "ne"})
	t.Cleanup(func() { active.Store(nil) })

	sc := targetSM()
	ReportEstablishment(sc)
	ReportEstablishment(sc) // a second UPF's response must not emit again

	if len(cap.pdus) != 1 {
		t.Errorf("establishment emitted %d records, want exactly 1", len(cap.pdus))
	}
}

// TestReportReleaseDeduplicates: a teardown that reaches both the
// update-initiated delete and the dedicated release handler must emit only one
// SMFPDUSessionRelease xIRI.
func TestReportReleaseDeduplicates(t *testing.T) {
	cap := &captureSender{}
	st := store.New()
	st.Activate(types.InterceptTask{
		XID:      "task-iri",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	})
	active.Store(&subsystem{store: st, senderFor: func(string) sender { return cap }, mdf2: configuredMDF2, iriCtx: iri.NewContext(), neID: "ne"})
	t.Cleanup(func() { active.Store(nil) })

	sc := targetSM()
	ReportRelease(sc)
	ReportRelease(sc) // second call for the same teardown must be a no-op
	if len(cap.pdus) != 1 {
		t.Fatalf("release emitted %d xIRI, want exactly 1 (dedupe)", len(cap.pdus))
	}
}

func TestApplyCCTriggerInactiveNoop(t *testing.T) {
	// With LI inactive, the trigger must not touch the session (and not panic on
	// a nil tunnel).
	far := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}}
	ApplyCCTrigger(ccSession(far))
	if far.ApplyAction.Dupl {
		t.Error("LI inactive: DUPL must not be set")
	}
	ApplyCCTrigger(&smfctx.SMContext{}) // nil tunnel, must not panic
}

// TestDeliveryIsolation checks multi-agency isolation on the SMF IRI path: two
// agencies tasking the same target each receive exactly their own xIRI tagged
// with their own XID (no cross-delivery), and a CC-only warrant never leaks into
// IRI (X2) delivery.
func TestDeliveryIsolation(t *testing.T) {
	const (
		xidA  = "aaaaaaaa-0000-0000-0000-000000000001"
		xidB  = "bbbbbbbb-0000-0000-0000-000000000002"
		xidCC = "cccccccc-0000-0000-0000-000000000003"
	)
	target := types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"}
	st := store.New()
	st.Activate(types.InterceptTask{XID: xidA, Targets: []types.TargetIdentifier{target}, Products: []types.ProductType{types.ProductIRI}, State: types.TaskActive})
	st.Activate(types.InterceptTask{XID: xidB, Targets: []types.TargetIdentifier{target}, Products: []types.ProductType{types.ProductIRI}, State: types.TaskActive})
	st.Activate(types.InterceptTask{XID: xidCC, Targets: []types.TargetIdentifier{target}, Products: []types.ProductType{types.ProductCC}, State: types.TaskActive})

	cap := &captureSender{}
	active.Store(&subsystem{store: st, senderFor: func(string) sender { return cap }, mdf2: configuredMDF2, iriCtx: iri.NewContext()})
	t.Cleanup(func() { active.Store(nil) })

	ReportEstablishment(targetSM())

	if len(cap.pdus) != 2 {
		t.Fatalf("delivered %d xIRI PDUs, want 2 (the two IRI agencies; CC-only excluded)", len(cap.pdus))
	}
	count := map[[16]byte]int{}
	for _, p := range cap.pdus {
		count[p.XID]++
	}
	if count[parseXID(xidA)] != 1 || count[parseXID(xidB)] != 1 {
		t.Errorf("each IRI agency must receive its own xIRI exactly once; XID counts = %v", count)
	}
	if count[parseXID(xidCC)] != 0 {
		t.Error("CC-only warrant leaked into IRI (X2) delivery")
	}
}

// TestEncodeAllEvents verifies every SMF xIRI a reporter can produce encodes
// through the real TS 33.128 context without error — mandatory members present,
// CHOICE arms registered. The correctness check a pure-mapping test can't give.
func TestEncodeAllEvents(t *testing.T) {
	sc := targetSM()
	ctx := iri.NewContext()
	events := map[string]any{
		"establishment":         smfEstablishment(sc),
		"modification":          smfModification(sc),
		"release":               smfRelease(sc),
		"start-of-interception": smfStartOfInterception(sc),
	}
	for name, ev := range events {
		if _, err := iri.EncodeXIRI(ctx, ev); err != nil {
			t.Errorf("encode %s: %v", name, err)
		}
	}
}

// subWith returns a subsystem backed by a store holding the given tasks (no X1
// server, no client) — for exercising the mid-session helpers directly.
func subWith(t *testing.T, tasks ...types.InterceptTask) *subsystem {
	t.Helper()
	st := store.New()
	for _, task := range tasks {
		if !st.Activate(task) {
			t.Fatalf("activate %+v", task)
		}
	}
	return &subsystem{store: st}
}

// TestApplyCCActivation covers the mid-session CC switch-on: a CC task
// targeting a live session sets DUPL and marks the FAR RULE_UPDATE so a PFCP
// modification re-sends it, and it is idempotent (a second call is a no-op).
func TestApplyCCActivation(t *testing.T) {
	target := types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"}
	sub := subWith(t, types.InterceptTask{
		XID: "cc", Targets: []types.TargetIdentifier{target},
		Products: []types.ProductType{types.ProductCC}, State: types.TaskActive,
	})

	far := &smfctx.FAR{ApplyAction: smfctx.ApplyAction{Forw: true}, State: smfctx.RULE_CREATE}
	sc := ccSession(far)

	if !sub.applyCC(sc) {
		t.Fatal("applyCC must report a change when switching duplication on")
	}
	if !far.ApplyAction.Dupl || far.State != smfctx.RULE_UPDATE {
		t.Errorf("want DUPL set + RULE_UPDATE, got dupl=%v state=%v", far.ApplyAction.Dupl, far.State)
	}
	if sub.applyCC(sc) {
		t.Error("applyCC must be idempotent: no change on the second call")
	}
}

// TestApplyCCDeactivation covers the mid-session CC switch-off: with no
// CC task left in the store, applyCC clears DUPL on a FAR that was duplicating and
// marks it RULE_UPDATE so the clear is pushed to the UPF.
func TestApplyCCDeactivation(t *testing.T) {
	sub := subWith(t) // empty store: target is no longer CC-tasked

	far := &smfctx.FAR{
		ApplyAction:           smfctx.ApplyAction{Forw: true, Dupl: true},
		DuplicatingParameters: &smfctx.DuplicatingParameters{},
		State:                 smfctx.RULE_CREATE,
	}
	sc := ccSession(far)

	if !sub.applyCC(sc) {
		t.Fatal("applyCC must report a change when clearing duplication")
	}
	if far.ApplyAction.Dupl || far.DuplicatingParameters != nil || far.State != smfctx.RULE_UPDATE {
		t.Errorf("want DUPL cleared + RULE_UPDATE, got dupl=%v params=%v state=%v",
			far.ApplyAction.Dupl, far.DuplicatingParameters, far.State)
	}
}

// TestApplyCCMultiAgency: while any CC task still targets the session, deactivating
// one CC warrant must leave duplication on (no change reported).
func TestApplyCCMultiAgency(t *testing.T) {
	target := types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"}
	// One CC task remains after the other agency's warrant was removed.
	sub := subWith(t, types.InterceptTask{
		XID: "cc-b", Targets: []types.TargetIdentifier{target},
		Products: []types.ProductType{types.ProductCC}, State: types.TaskActive,
	})

	far := &smfctx.FAR{
		ApplyAction:           smfctx.ApplyAction{Forw: true, Dupl: true},
		DuplicatingParameters: &smfctx.DuplicatingParameters{},
		State:                 smfctx.RULE_CREATE,
	}
	if sub.applyCC(ccSession(far)) {
		t.Error("duplication must stay on while another CC warrant targets the session")
	}
	if !far.ApplyAction.Dupl {
		t.Error("DUPL must remain set for the still-tasked target")
	}
}

func TestSessionTargets(t *testing.T) {
	sc := ccSession(&smfctx.FAR{}) // Supi = imsi-262019876543210
	if !sessionTargets(types.InterceptTask{Targets: []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}}}, sc) {
		t.Error("a SUPI target must match the session's SUPI")
	}
	if sessionTargets(types.InterceptTask{Targets: []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "111111111111111"}}}, sc) {
		t.Error("a non-matching SUPI must not match")
	}
}

// TestEstablishmentReportsTheRealRequestAndAccessType: both fields are mandatory
// in the TS 33.128 establishment record and both used to be hard-coded, so every
// session reached the law-enforcement agency described as an initial request over
// 3GPP access — hiding an emergency session, and misstating whether the UE asked
// for a new session or resumed an existing one.
func TestEstablishmentReportsTheRealRequestAndAccessType(t *testing.T) {
	cases := []struct {
		request models.RequestType
		access  models.AccessType
		wantReq iri.FiveGSMRequestType
		wantAcc iri.AccessType
	}{
		{models.REQUESTTYPE_INITIAL_REQUEST, models.ACCESSTYPE__3_GPP_ACCESS, iri.SMRequestInitial, iri.AccessThreeGPP},
		{models.REQUESTTYPE_EXISTING_PDU_SESSION, models.ACCESSTYPE__3_GPP_ACCESS, iri.SMRequestExisting, iri.AccessThreeGPP},
		{models.REQUESTTYPE_INITIAL_EMERGENCY_REQUEST, models.ACCESSTYPE__3_GPP_ACCESS, iri.SMRequestInitialEmergency, iri.AccessThreeGPP},
		{models.REQUESTTYPE_EXISTING_EMERGENCY_PDU_SESSION, models.ACCESSTYPE_NON_3_GPP_ACCESS, iri.SMRequestExistingEmergency, iri.AccessNonThreeGPP},
		// An unset request type is the closest thing to "initial" available, but the
		// access type must still be reported as configured.
		{"", models.ACCESSTYPE_NON_3_GPP_ACCESS, iri.SMRequestInitial, iri.AccessNonThreeGPP},
	}

	for _, c := range cases {
		sc := targetSM()
		sc.RequestType = c.request
		sc.AnType = c.access

		rec := smfEstablishment(sc)
		if rec.RequestType != c.wantReq {
			t.Errorf("RequestType for %q = %d, want %d", c.request, rec.RequestType, c.wantReq)
		}
		if rec.AccessType != c.wantAcc {
			t.Errorf("AccessType for %q = %d, want %d", c.access, rec.AccessType, c.wantAcc)
		}

		// The modification and start-of-interception records carry the same access
		// type; their request types are fixed by what the record means.
		if got := smfModification(sc).AccessType; got != c.wantAcc {
			t.Errorf("modification AccessType for %q = %d, want %d", c.access, got, c.wantAcc)
		}
		if got := smfStartOfInterception(sc).AccessType; got != c.wantAcc {
			t.Errorf("start-of-interception AccessType for %q = %d, want %d", c.access, got, c.wantAcc)
		}
	}
}

// configuredMDF2 stands in for the endpoint an SMF is configured with. It is deliberately
// not any task's own destination in the tests below, so that "delivered to the task's
// endpoint" and "delivered to configuration" are distinguishable outcomes — with one
// address they are not, which is why this defect survived a passing suite.
const configuredMDF2 = "10.0.60.99:42069"

// addressCapture records what was delivered and where.
type addressCapture struct {
	mu   sync.Mutex
	sent map[string][][16]byte
}

func newAddressCapture() *addressCapture {
	return &addressCapture{sent: map[string][][16]byte{}}
}

func (c *addressCapture) senderFor(addr string) sender {
	return senderFunc(func(p *x2x3.PDU) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.sent[addr] = append(c.sent[addr], p.XID)

		return nil
	})
}

type senderFunc func(*x2x3.PDU) error

func (f senderFunc) Send(p *x2x3.PDU) error { return f(p) }

// TestXIRIGoesToTheDestinationsTheTaskNamed is the SMF half of the conformance fix, and
// the same assertion as the AMF's: two warrants provisioned to two agencies, and neither
// agency receives the other's session.
func TestXIRIGoesToTheDestinationsTheTaskNamed(t *testing.T) {
	const (
		xidA    = "aaaaaaaa-0000-0000-0000-000000000001"
		xidB    = "bbbbbbbb-0000-0000-0000-000000000002"
		agencyA = "10.0.60.122:42069"
		agencyB = "10.0.60.123:42070"
	)
	target := types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"}
	st := store.New()
	for _, c := range []struct{ xid, addr string }{{xidA, agencyA}, {xidB, agencyB}} {
		st.Activate(types.InterceptTask{
			XID: types.XID(c.xid), Targets: []types.TargetIdentifier{target},
			Products:   []types.ProductType{types.ProductIRI},
			Deliveries: []types.DeliveryEndpoint{{Type: types.DeliveryX2, Address: c.addr}},
			State:      types.TaskActive,
		})
	}

	capture := newAddressCapture()
	active.Store(&subsystem{
		store: st, senderFor: capture.senderFor, mdf2: configuredMDF2, iriCtx: iri.NewContext(),
	})
	t.Cleanup(func() { active.Store(nil) })

	ReportEstablishment(targetSM())

	for _, c := range []struct{ addr, xid string }{{agencyA, xidA}, {agencyB, xidB}} {
		got := capture.sent[c.addr]
		if len(got) != 1 {
			t.Errorf("%s received %d records, want 1", c.addr, len(got))

			continue
		}
		if got[0] != parseXID(types.XID(c.xid)) {
			t.Errorf("%s received a record for a warrant it was not provisioned for", c.addr)
		}
	}
	if n := len(capture.sent[configuredMDF2]); n != 0 {
		t.Errorf("the configured endpoint received %d records, want 0: both tasks named a destination", n)
	}
}

// The configured endpoint still serves a task that named nothing resolvable, which is
// what every deployment predating the ListOfDIDs requirement relies on.
func TestATaskNamingNoDestinationFallsBackToConfiguration(t *testing.T) {
	st := store.New()
	st.Activate(types.InterceptTask{
		XID:      "aaaaaaaa-0000-0000-0000-000000000001",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	})

	capture := newAddressCapture()
	active.Store(&subsystem{
		store: st, senderFor: capture.senderFor, mdf2: configuredMDF2, iriCtx: iri.NewContext(),
	})
	t.Cleanup(func() { active.Store(nil) })

	ReportEstablishment(targetSM())

	if n := len(capture.sent[configuredMDF2]); n != 1 {
		t.Errorf("the configured endpoint received %d records, want 1", n)
	}
}

// TestDeliveryFaultIsReportedOnBothEdges covers this element's contribution to its own
// status answer, and all three assertions are the point rather than one of them.
//
// A probe stuck *off* leaves an element that has been failing to deliver for hours
// answering that nothing is wrong — invisible, and the reason an ADMF can ask at all. A
// probe stuck *on* makes every healthy element report itself faulty, which is noticed
// immediately and discredits the whole field; that is how this library's predecessor probe
// failed. So two of the three assertions below are about the probe staying quiet.
func TestDeliveryFaultIsReportedOnBothEdges(t *testing.T) {
	unreachable := 0
	sub := &subsystem{unreachable: func() (int, int) { return unreachable, 2 }}

	if fault := sub.deliveryFault(); fault != nil {
		t.Errorf("with both destinations reachable the element reports itself faulty: %q",
			fault.ErrorDescription)
	}

	unreachable = 1
	fault := sub.deliveryFault()
	if fault == nil {
		t.Fatal("with a destination unreachable the element reports no fault; an ADMF cannot " +
			"tell it apart from one delivering every record")
	}
	if !strings.Contains(fault.ErrorDescription, x1.NEIssueMDFUnreachable) {
		t.Errorf("the fault does not name the condition: %q", fault.ErrorDescription)
	}
	if !strings.Contains(fault.ErrorDescription, "1 of 2") {
		t.Errorf("the fault does not say how much is wrong: %q", fault.ErrorDescription)
	}

	// Nothing clears it. Delivery starts working and the next answer says so, which is the
	// property no design that remembers faults can offer.
	unreachable = 0
	if fault := sub.deliveryFault(); fault != nil {
		t.Errorf("the fault outlived the condition, with nothing having cleared it: %q",
			fault.ErrorDescription)
	}
}

// TestDeliveryFaultNamesNoDestination keeps the NE-level answer at NE level. This element
// may deliver two agencies' warrants to two MDF2s; TS 103 221-1 keeps an element's own
// status separate from per-destination and per-task faults, and an answer naming the failing
// address would put interception detail in a message that is not scoped to a warrant.
func TestDeliveryFaultNamesNoDestination(t *testing.T) {
	sub := &subsystem{unreachable: func() (int, int) { return 1, 2 }}

	fault := sub.deliveryFault()
	if fault == nil {
		t.Fatal("no fault reported for an unreachable destination")
	}
	for _, identity := range []string{"10.0.60.122", "42069", "208930100007488"} {
		if strings.Contains(fault.ErrorDescription, identity) {
			t.Errorf("the element's own status names %q; it must say how much is wrong, never whose",
				identity)
		}
	}
}

// TestDeliveryFaultWithNoAccountingIsSilent: an element that cannot say is not an element
// that is broken. The probe runs on the X1 request goroutine, where reporting a fault
// nobody observed — or panicking — are both worse than answering that nothing is known.
func TestDeliveryFaultWithNoAccountingIsSilent(t *testing.T) {
	if fault := (&subsystem{}).deliveryFault(); fault != nil {
		t.Errorf("an element with no delivery accounting reported a fault: %q", fault.ErrorDescription)
	}
}
