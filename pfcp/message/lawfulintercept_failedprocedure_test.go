// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"errors"
	"testing"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/wmnsk/go-pfcp/message"
)

// failingSession is an SM context registered in the SEID index, which is how both failure handlers
// find the session an unanswered PFCP request belonged to.
func failingSession(t *testing.T) (*smf_context.SMContext, uint64) {
	t.Helper()

	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}

		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	sc := smf_context.NewSMContext("imsi-262019876543210", 1)
	t.Cleanup(func() { smf_context.RemoveSMContext(sc.Ref) })

	node := smf_context.NewDataPathNode()
	node.UPF = &smf_context.UPF{NodeID: *smf_context.NewNodeID("10.0.1.5")}

	sc.Tunnel = &smf_context.UPTunnel{DataPathPool: smf_context.DataPathPool{
		1: &smf_context.DataPath{FirstDPNode: node, IsDefaultPath: true, Activated: true},
	}}
	sc.PFCPContext = map[string]*smf_context.PFCPSessionContext{}
	sc.AllocateLocalSEIDForDataPath(sc.Tunnel.DataPathPool[1])

	return sc, sc.PFCPContext["10.0.1.5"].LocalSEID
}

// TestAFailedEstablishmentSendIsReported covers the path that builds its own reject.
//
// The producer funnels its refusals through one helper precisely so a new rejection path cannot be
// added without the record. This path is older, sits below it, and was never joined to it: it
// builds a PDU Session Establishment Reject with 5GSM cause "request rejected, unspecified", sends
// it to the UE and removes the SM context, and reported nothing.
//
// For a tasked subject that means a session which failed because the user plane was unreachable
// produced no record at all — the agency sees exactly what it sees for a subject who never tried.
func TestAFailedEstablishmentSendIsReported(t *testing.T) {
	sc, seid := failingSession(t)

	var (
		reported *smf_context.SMContext
		gotCause uint8
	)

	restore := ReportEstablishmentReject
	ReportEstablishmentReject = func(reportedSc *smf_context.SMContext, cause uint8) {
		reported, gotCause = reportedSc, cause
	}

	t.Cleanup(func() { ReportEstablishmentReject = restore })

	handleSendPfcpSessEstReqError(
		message.NewSessionEstablishmentRequest(0, 0, seid, 1, 0),
		errors.New("no response from UPF"))

	if reported == nil {
		t.Fatal("a PDU session establishment that failed because the user plane did not answer " +
			"produced no unsuccessful-procedure record. The element built a reject, sent it to " +
			"the subject and removed the context, and told the agency nothing — which is what it " +
			"also says about a subject who never attempted a session")
	}

	if reported.Ref != sc.Ref {
		t.Errorf("the record names SM context %q, want the one that failed %q", reported.Ref, sc.Ref)
	}

	// The cause the element actually put in the reject, not one invented for the record.
	if gotCause == 0 {
		t.Error("the record carries no 5GSM cause, while the reject the subject received carries one")
	}
}

// TestAFailedModificationSendIsReported covers the counterpart to a record this element already
// emits.
//
// ReportModification is raised before the PFCP modification is attempted — a legitimate choice,
// since the state the record describes may be gone by the time the outcome is known, and one that
// obliges the element to report the failure that follows. Without this the agency held a record
// asserting a modification that never took effect, with nothing to say so. The release path has
// handled exactly this shape on all three of its failure branches since it was written.
func TestAFailedModificationSendIsReported(t *testing.T) {
	sc, seid := failingSession(t)

	// The handler hands the outcome to the producer over this channel; nothing reads it here.
	sc.SBIPFCPCommunicationChan = make(chan smf_context.PFCPSessionResponseStatus, 1)

	var reported *smf_context.SMContext

	restore := ReportModificationReject
	ReportModificationReject = func(reportedSc *smf_context.SMContext, _ uint8) {
		reported = reportedSc
	}

	t.Cleanup(func() { ReportModificationReject = restore })

	handleSendPfcpSessModReqError(
		message.NewSessionModificationRequest(0, 0, seid, 1, 0),
		errors.New("no response from UPF"))

	if reported == nil {
		t.Fatal("a PDU session modification that failed because the user plane did not answer " +
			"produced no unsuccessful-procedure record, while the modification record emitted " +
			"before the send stands. The agency is left holding a record asserting a change that " +
			"never took effect, with no counterpart")
	}

	if reported.Ref != sc.Ref {
		t.Errorf("the record names SM context %q, want the one that failed %q", reported.Ref, sc.Ref)
	}
}
