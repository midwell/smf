// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler_test

import (
	"net"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/handler"
	"github.com/omec-project/smf/pfcp/lisequence"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type Flag uint8

// setBit sets the bit at the given position to the specified value (true or false)
// Positions go from 1 to 8
func (f *Flag) setBit(position uint8) {
	if position < 1 || position > 8 {
		return
	}
	*f |= 1 << (position - 1)
}

func boolPointer(b bool) *bool {
	return &b
}

func TestFindUEIPAddressNoAddressInCreatedPDR(t *testing.T) {
	sessionEstablishmentResponse := message.NewSessionEstablishmentResponse(
		0,
		0,
		0,
		0,
		0,
		ie.NewCreatedPDR(
			ie.NewPDRID(12345),
		),
	)

	createdPDRIEs := sessionEstablishmentResponse.CreatedPDR

	ipAddress := handler.FindUEIPAddress(createdPDRIEs)

	if ipAddress != nil {
		t.Errorf("Expected nil, got %v", ipAddress)
	}
}

func TestFindUEIPAddressNoUEIPAddressInCreatedPDR(t *testing.T) {
	ueIPAddressFlags := new(Flag)
	ueIPAddressFlags.setBit(2)
	sessionEstablishmentResponse := message.NewSessionEstablishmentResponse(
		0,
		0,
		0,
		0,
		0,
		ie.NewCreatedPDR(
			ie.NewPDRID(12345),
			ie.NewUEIPAddress(uint8(*ueIPAddressFlags), "1.2.3.4", "", 0, 0),
		),
	)

	createdPDRIEs := sessionEstablishmentResponse.CreatedPDR

	ipAddress := handler.FindUEIPAddress(createdPDRIEs)

	if !ipAddress.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("Expected %v, got %v", "1.2.3.4", ipAddress)
	}
}

func TestHandlePfcpAssociationSetupResponse(t *testing.T) {
	kafkaInfo := factory.KafkaInfo{
		EnableKafka: boolPointer(false),
	}
	configuration := &factory.Configuration{
		KafkaInfo:        kafkaInfo,
		EnableUpfAdapter: false,
	}
	factory.SmfConfig = factory.Config{
		Configuration: configuration,
	}
	upNodeID := context.NewNodeID("1.1.1.1")
	upf := context.NewUPF(upNodeID, nil)
	SnssaiInfos := make([]context.SnssaiUPFInfo, 0)
	snssaiInfo := context.SnssaiUPFInfo{
		DnnList: []context.DnnUPFInfoItem{
			{
				Dnn: "internet",
			},
		},
	}
	SnssaiInfos = append(SnssaiInfos, snssaiInfo)
	upf.SNssaiInfos = SnssaiInfos
	pfcp_message.InsertPfcpTxn(1, upNodeID)
	recoveryTimestamp := time.Now()
	msg := message.NewAssociationSetupResponse(
		1,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("1.1.1.1", "", ""),
		ie.NewRecoveryTimeStamp(recoveryTimestamp),
	)

	remoteAddress := &net.UDPAddr{
		IP:   net.ParseIP("1.1.1.1"),
		Port: 8810,
	}
	udpMessage := udp.Message{
		RemoteAddr:  remoteAddress,
		PfcpMessage: msg,
	}

	handler.HandlePfcpAssociationSetupResponse(&udpMessage)

	if upf.UPFStatus != context.AssociatedSetUpSuccess {
		t.Errorf("Expected UPFStatus %v, got %v", context.AssociatedSetUpSuccess, upf.UPFStatus)
	}
	if upf.RecoveryTimeStamp.RecoveryTimeStamp.Truncate(1*time.Second) != recoveryTimestamp.Truncate(1*time.Second) {
		t.Errorf("Expected RecoveryTimeStamp %v, got %v", recoveryTimestamp.Truncate(1*time.Second), upf.RecoveryTimeStamp.RecoveryTimeStamp.Truncate(1*time.Second))
	}
}

func TestHandlePfcpSessionEstablishmentResponse(t *testing.T) {
	recoveryTimestamp := time.Now()
	nodeID := context.NewNodeID("1.1.1.1")
	smContext := context.NewSMContext("imsi-123456789012345", 10)

	smContext.Tunnel = &context.UPTunnel{
		DataPathPool: context.DataPathPool{
			10: &context.DataPath{
				IsDefaultPath: true,
				FirstDPNode: &context.DataPathNode{
					UPF: &context.UPF{},
					UpLinkTunnel: &context.GTPTunnel{
						TEID: 0,
					},
				},
			},
		},
		ANInformation: struct {
			IPAddress net.IP
			TEID      uint32
		}{
			IPAddress: net.ParseIP("192.168.1.1"),
			TEID:      0,
		},
	}

	smContext.PFCPContext = map[string]*context.PFCPSessionContext{
		nodeID.ResolveNodeIdToIp().String(): {
			RemoteSEID: 12345,
		},
	}

	datapath := &context.DataPath{
		FirstDPNode: &context.DataPathNode{
			UPF: &context.UPF{},
		},
	}
	smContext.AllocateLocalSEIDForDataPath(datapath)
	pfcp_message.InsertPfcpTxn(1, nodeID)

	rsp := message.NewSessionEstablishmentResponse(
		0,
		0,
		1,
		1,
		0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("1.1.1.1", "", ""),
		ie.NewRecoveryTimeStamp(recoveryTimestamp),
		ie.NewCreatedPDR(
			ie.NewFTEID(0, 4321, net.ParseIP("192.168.1.1"), nil, 0),
		),
	)

	udpMessage := udp.Message{
		RemoteAddr: &net.UDPAddr{
			IP:   net.ParseIP("1.1.1.1"),
			Port: 8809,
		},
		PfcpMessage: rsp,
	}

	handler.HandlePfcpSessionEstablishmentResponse(&udpMessage)

	if smContext.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode.UpLinkTunnel.TEID != 4321 {
		t.Errorf("Expected TEID 4321, got %d", smContext.Tunnel.ANInformation.TEID)
	}

	expectedIP := net.ParseIP("192.168.1.1")
	if !smContext.Tunnel.ANInformation.IPAddress.Equal(expectedIP) {
		t.Errorf("Expected ANInformation IP %v, got %v", expectedIP, smContext.Tunnel.ANInformation.IPAddress)
	}
}

// TestHandlePfcpSessionEstablishmentResponseNilTunnel covers the defensive
// guard for a stale Session Establishment Response arriving after the Tunnel
// has been nilled (e.g. by releaseTunnel). The handler must not panic on the
// nil Tunnel and must consume the pending PFCP txn on the ignore path so it is
// not leaked.
func TestHandlePfcpSessionEstablishmentResponseNilTunnel(t *testing.T) {
	// AllocateLocalSEID reads factory.SmfConfig.Configuration.EnableDbStore, so
	// the config must be initialized for the SEID allocation path not to panic
	// when this test runs in isolation.
	if factory.SmfConfig.Configuration == nil {
		factory.SmfConfig = factory.Config{
			Configuration: &factory.Configuration{
				KafkaInfo:        factory.KafkaInfo{EnableKafka: boolPointer(false)},
				EnableUpfAdapter: false,
			},
		}
	}

	nodeID := context.NewNodeID("2.2.2.2")
	smContext := context.NewSMContext("imsi-123456789012399", 20)

	// Register the context in the SEID lookup map by allocating a local SEID
	// for a data path, mirroring what HandlePDUSessionSMContextCreate does
	// before sending the PFCP Establishment Request.
	datapath := &context.DataPath{
		FirstDPNode: &context.DataPathNode{
			UPF: &context.UPF{NodeID: *nodeID},
		},
	}
	smContext.AllocateLocalSEIDForDataPath(datapath)

	// Read the allocated SEID back so the lookup in the handler succeeds
	// regardless of the global allocation counter (test ordering).
	var localSEID uint64
	for _, pfcpCtx := range smContext.PFCPContext {
		if pfcpCtx.LocalSEID != 0 {
			localSEID = pfcpCtx.LocalSEID
		}
	}
	if localSEID == 0 {
		t.Fatal("failed to allocate a local SEID for the test SMContext")
	}

	// Simulate the realistic failure case: Tunnel nilled while a stale
	// Establishment Response is still in flight.
	smContext.Tunnel = nil

	const seq uint32 = 0x424242
	pfcp_message.InsertPfcpTxn(seq, nodeID)

	rsp := message.NewSessionEstablishmentResponse(
		0,
		0,
		localSEID,
		seq,
		0,
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewNodeID("2.2.2.2", "", ""),
		ie.NewRecoveryTimeStamp(time.Now()),
	)

	udpMessage := udp.Message{
		RemoteAddr: &net.UDPAddr{
			IP:   net.ParseIP("2.2.2.2"),
			Port: 8809,
		},
		PfcpMessage: rsp,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handler panicked on nil Tunnel (guard regression?): %v", r)
		}
	}()

	handler.HandlePfcpSessionEstablishmentResponse(&udpMessage)

	if leaked := pfcp_message.FetchPfcpTxn(seq); leaked != nil {
		t.Errorf("expected pending PFCP txn for seq %d to be consumed on the nil-Tunnel ignore path, but it was still present", seq)
	}
}

// modificationResponse builds an accepted Session Modification Response carrying
// the given sequence number, addressed to seid.
func modificationResponse(seq uint32, seid uint64) *udp.Message {
	return &udp.Message{
		RemoteAddr:  &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 8805},
		PfcpMessage: message.NewSessionModificationResponse(0, 0, seid, seq, 0, ie.NewCause(ie.CauseRequestAccepted)),
	}
}

// TestLIModificationResponseDoesNotCompleteTheSessionsOwnProcedure is the
// interleaving the correlation could not see. A modification sent for Lawful
// Interception and one sent by the subscriber's own procedure differ in nothing
// the response path reads — same SEID, same UPF, same message type — so the LI
// answer used to clear the pending entry the subscriber's procedure was waiting
// on and report that procedure complete before its own answer had arrived.
//
// Interception is permitted to lose a copy or decline a record. It is not
// permitted to change what happens to the subscriber.
func TestLIModificationResponseDoesNotCompleteTheSessionsOwnProcedure(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	nodeID := context.NewNodeID("1.1.1.1")
	upfIP := nodeID.ResolveNodeIdToIp().String()
	smContext := context.NewSMContext("imsi-123456789012399", 11)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })

	datapath := &context.DataPath{FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}}}
	smContext.AllocateLocalSEIDForDataPath(datapath)
	seid := smContext.PFCPContext[upfIP].LocalSEID

	// The subscriber's own modification is outstanding to this UPF.
	smContext.ChangeState(context.SmStatePfcpModify)
	smContext.PendingUPF = context.PendingUPF{upfIP: true}

	// An LI modification goes out while it is: a warrant changed, which happens on
	// the provisioning plane's schedule and not the session's.
	const liSeq = uint32(4242)
	// The request the modification carried, as the send site records it: the answer is
	// correlated with what was asked, because the send clears the FAR state that would
	// otherwise say.
	lisequence.Mark(liSeq, lisequence.Request{SEID: seid, NodeID: "1.1.1.1", Duplicating: true})

	handler.HandlePfcpSessionModificationResponse(modificationResponse(liSeq, seid))

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

// TestOrdinaryModificationResponseStillCompletes is the other side of the guard:
// the early return must recognise only LI-originated sequences, or every ordinary
// modification stops being answered and every session update hangs.
func TestOrdinaryModificationResponseStillCompletes(t *testing.T) {
	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}

	nodeID := context.NewNodeID("1.1.1.1")
	upfIP := nodeID.ResolveNodeIdToIp().String()
	smContext := context.NewSMContext("imsi-123456789012398", 12)
	t.Cleanup(func() { context.RemoveSMContext(smContext.Ref) })

	datapath := &context.DataPath{FirstDPNode: &context.DataPathNode{UPF: &context.UPF{NodeID: *nodeID}}}
	smContext.AllocateLocalSEIDForDataPath(datapath)
	seid := smContext.PFCPContext[upfIP].LocalSEID

	smContext.ChangeState(context.SmStatePfcpModify)
	smContext.PendingUPF = context.PendingUPF{upfIP: true}
	smContext.SBIPFCPCommunicationChan = make(chan context.PFCPSessionResponseStatus, 1)

	handler.HandlePfcpSessionModificationResponse(modificationResponse(7, seid))

	if !smContext.PendingUPF.IsEmpty() {
		t.Fatal("an ordinary modification response did not clear its pending UPF")
	}
	select {
	case got := <-smContext.SBIPFCPCommunicationChan:
		if got != context.SessionUpdateSuccess {
			t.Errorf("session update signalled %v, want success", got)
		}
	default:
		t.Error("an ordinary modification response did not complete the session's procedure")
	}
}
