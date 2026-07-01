// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"bytes"
	"testing"

	"github.com/omec-project/li/iri"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/openapi/v2/models"
	smfctx "github.com/omec-project/smf/context"
)

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
		Target:   types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"},
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
		Target:   types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"},
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
		Target:   types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"},
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

// TestEncodeAllEvents verifies every SMF xIRI a reporter can produce encodes
// through the real TS 33.128 context without error — mandatory members present,
// CHOICE arms registered. The correctness check a pure-mapping test can't give.
func TestEncodeAllEvents(t *testing.T) {
	sc := targetSM()
	ctx := iri.NewContext()
	events := map[string]any{
		"establishment": smfEstablishment(sc),
		"modification":  smfModification(sc),
		"release":       smfRelease(sc),
	}
	for name, ev := range events {
		if _, err := iri.EncodeXIRI(ctx, ev); err != nil {
			t.Errorf("encode %s: %v", name, err)
		}
	}
}
