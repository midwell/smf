// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"net"
	"testing"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/lisequence"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// modificationResponse builds an accepted Session Modification Response carrying the
// given sequence number, addressed to seid.
func modificationResponse(seq uint32, seid uint64) *udp.Message {
	return &udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 8805},
		PfcpMessage: message.NewSessionModificationResponse(0, 0, seid, seq, 0, ie.NewCause(ie.CauseRequestAccepted)),
	}
}

func modifyingSession(t *testing.T) (*context.SMContext, uint64) {
	t.Helper()

	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	nodeID := context.NewNodeID("1.1.1.1")
	upfIP := nodeID.ResolveNodeIdToIp().String()
	smContext := context.NewSMContext("imsi-123456789012399", 12)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })

	datapath := &context.DataPath{FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}}}
	smContext.AllocateLocalSEIDForDataPath(datapath)
	seid := smContext.PFCPContext[upfIP].LocalSEID

	// The subscriber's own modification is outstanding to this UPF.
	smContext.ChangeState(context.SmStatePfcpModify)
	smContext.PendingUPF = context.PendingUPF{upfIP: true}

	return smContext, seid
}

// TestLIModificationResponseDoesNotCompleteTheSessionsOwnProcedureInAdapterMode is the
// native handler's guard, asserted on the path taken when enableUPFAdapter is set.
//
// The two handlers do the same correlation and only one of them recognised an
// LI-originated answer. In adapter mode sendSessionModification routes the response
// here, so an LI modification's answer landing during the subscriber's own
// modification cleared the pending entry that procedure was waiting on and completed
// it — interception-driven signalling mistaken for the session's own, which is the one
// thing interception may never do. Nothing about the deployment mode changes that;
// only which function saw the message.
func TestLIModificationResponseDoesNotCompleteTheSessionsOwnProcedureInAdapterMode(t *testing.T) {
	smContext, seid := modifyingSession(t)

	// An LI modification goes out while the subscriber's is outstanding: a warrant
	// changed, which happens on the provisioning plane's schedule and not the session's.
	const liSeq = uint32(5252)
	// The request the modification carried, as the send site records it: the answer is
	// correlated with what was asked, because the send clears the FAR state that would
	// otherwise say.
	lisequence.Mark(liSeq, lisequence.Request{SEID: seid, NodeID: "1.1.1.1", Duplicating: true})

	adapter.HandlePfcpSessionModificationResponse(modificationResponse(liSeq, seid))

	if smContext.PendingUPF.IsEmpty() {
		t.Error("the LI modification's answer cleared the UPF the subscriber's own " +
			"modification was waiting on — that procedure would now complete on an " +
			"answer that was never sent to it")
	}
	select {
	case <-smContext.SBIPFCPCommunicationChan:
		t.Error("the LI modification's answer completed the session's own procedure")
	default:
	}
}

// TestOrdinaryModificationResponseStillCompletesInAdapterMode is the other side of the
// guard: it must recognise only LI-originated sequences, or in adapter mode every
// ordinary modification stops being answered and every session update hangs.
func TestOrdinaryModificationResponseStillCompletesInAdapterMode(t *testing.T) {
	smContext, seid := modifyingSession(t)

	adapter.HandlePfcpSessionModificationResponse(modificationResponse(7373, seid))

	if !smContext.PendingUPF.IsEmpty() {
		t.Error("an ordinary modification's answer did not clear the UPF it came from")
	}
	select {
	case <-smContext.SBIPFCPCommunicationChan:
	default:
		t.Error("an ordinary modification's answer did not complete the session's procedure")
	}
}
