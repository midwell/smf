// SPDX-FileCopyrightText: 2022-present Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package adapter

import (
	"fmt"
	"net"
	"sync"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/pfcp/lisequence"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func init() {
	PfcpTxns = make(map[uint32]*context.NodeID)
}

// POIRestarted is the Lawful Interception hook this package calls when a UPF's recovery
// timestamp shows it restarted, or when it stops answering. Nil unless LI is wired, and
// nil-checked at every call site.
//
// **A package variable rather than a direct call, because this package may not import
// lawfulintercept.** pfcp/message imports this one, and lawfulintercept's own tests import
// pfcp/message, so the direct call is an import cycle. The same shape the producer's
// teardown hooks take, for the same reason, and it is assigned once by the service wiring
// that already builds the LI subsystem.
var POIRestarted func(node context.NodeID, addr string)

// LIModificationAnswered is the Lawful Interception hook this package calls with the
// outcome of a modification the interception subsystem sent. Nil unless LI is wired, and
// assigned by the same service wiring that assigns POIRestarted, for the same reason: this
// package may not import lawfulintercept.
var LIModificationAnswered func(req lisequence.Request, cause uint8, answered bool)

// notifyLIModificationAnswered calls the hook if one is wired.
func notifyLIModificationAnswered(req lisequence.Request, cause uint8, answered bool) {
	if LIModificationAnswered != nil {
		LIModificationAnswered(req, cause, answered)
	}
}

// ReportEstablishment, ApplyCCAfterEstablishment and TriggerCC are the Lawful Interception hooks
// this package raises when a PFCP session establishment response completes. They are assigned by
// the same service wiring that assigns POIRestarted, for the same reason: this package may not
// import lawfulintercept.
//
// **They exist because only one of the native and adapter handlers runs in a deployment.** The
// native handler in pfcp/handler has carried these three since interception was built; this one
// had none of them, so with enableUPFAdapter set — the chart's default — the SMF sent the UPF a
// DUPL FAR and then never sent the ActivateTask that authorises it. The CC-POI held no task for
// the session, dropped every copy as unattributable, and the establishment record was never
// produced. Nothing anywhere raised a fault, because from the SMF's side nothing had failed.
var (
	ReportEstablishment       func(sc *context.SMContext)
	ApplyCCAfterEstablishment func(sc *context.SMContext)
	TriggerCC                 func(sc *context.SMContext)
)

// notifyReportEstablishment calls the hook if one is wired.
func notifyReportEstablishment(sc *context.SMContext) {
	if ReportEstablishment != nil {
		ReportEstablishment(sc)
	}
}

// notifyApplyCCAfterEstablishment calls the hook if one is wired.
func notifyApplyCCAfterEstablishment(sc *context.SMContext) {
	if ApplyCCAfterEstablishment != nil {
		ApplyCCAfterEstablishment(sc)
	}
}

// notifyTriggerCC calls the hook if one is wired.
//
// One helper per hook, named for it, rather than one that raises both: the call site is what a
// reader and a parity check both look at, and a helper that groups two hooks hides their names
// from it. That is not hypothetical either — the first version of this grouped them, and the
// parity guard in this package failed until they were named here.
func notifyTriggerCC(sc *context.SMContext) {
	if TriggerCC != nil {
		TriggerCC(sc)
	}
}

// establishmentAccepted reports whether the response carries an accepted cause.
//
// A copy of pfcp/handler's helper rather than a shared one: this package cannot import that one
// without a cycle, and the alternative — moving the shared response handling into a package both
// can import — is a restructuring of upstream code on a fork that must stay readable as a diff.
func establishmentAccepted(rsp *message.SessionEstablishmentResponse) bool {
	if rsp.Cause == nil {
		return false
	}

	cause, err := rsp.Cause.Cause()

	return err == nil && cause == ie.CauseRequestAccepted
}

// notifyPOIRestarted calls the hook if one is wired. Written once so a new call site cannot
// forget the nil check — a nil function value panics, and these are PFCP message handlers.
func notifyPOIRestarted(node context.NodeID, addr string) {
	if POIRestarted != nil {
		POIRestarted(node, addr)
	}
}

var (
	PfcpTxns    map[uint32]*context.NodeID
	PfcpTxnLock sync.Mutex
)

func FetchPfcpTxn(seqNo uint32) (upNodeID *context.NodeID) {
	PfcpTxnLock.Lock()
	defer PfcpTxnLock.Unlock()
	if upNodeID = PfcpTxns[seqNo]; upNodeID != nil {
		delete(PfcpTxns, seqNo)
	}
	return upNodeID
}

func InsertPfcpTxn(seqNo uint32, upNodeID *context.NodeID) {
	PfcpTxnLock.Lock()
	defer PfcpTxnLock.Unlock()
	PfcpTxns[seqNo] = upNodeID
}

/*
This function is called when smf runs with upfadapter and the communication between

	them is sync. smf already holds the lock before calling to the below API, so not required
	upfLock in handler functions
*/
func HandleAdapterPfcpRsp(pfcpMsg message.Message, evtData *udp.PfcpEventData) error {
	switch pfcpMsg.MessageType() {
	case message.MsgTypeAssociationSetupResponse:
		msg := udp.Message{PfcpMessage: pfcpMsg}
		HandlePfcpAssociationSetupResponse(&msg)
	case message.MsgTypeHeartbeatResponse:
		msg := udp.Message{PfcpMessage: pfcpMsg}
		HandlePfcpHeartbeatResponse(&msg)
	case message.MsgTypeSessionEstablishmentResponse:
		msg := udp.Message{PfcpMessage: pfcpMsg, EventData: *evtData}
		HandlePfcpSessionEstablishmentResponse(&msg)
	case message.MsgTypeSessionModificationResponse:
		msg := udp.Message{PfcpMessage: pfcpMsg, EventData: *evtData}
		HandlePfcpSessionModificationResponse(&msg)
	case message.MsgTypeSessionDeletionResponse:
		msg := udp.Message{PfcpMessage: pfcpMsg, EventData: *evtData}
		HandlePfcpSessionDeletionResponse(&msg)
	default:
		logger.PfcpLog.Errorf("upf adapter invalid msg type: %v", pfcpMsg)
	}
	return nil
}

func FindUEIPAddress(createdPDRIEs []*ie.IE) net.IP {
	for _, createdPDRIE := range createdPDRIEs {
		ueIPAddress, err := createdPDRIE.UEIPAddress()
		if err == nil {
			return ueIPAddress.IPv4Address
		}
	}
	return nil
}

func FindFTEID(createdPDRIEs []*ie.IE) (*ie.FTEIDFields, error) {
	for _, createdPDRIE := range createdPDRIEs {
		teid, err := createdPDRIE.FTEID()
		if err == nil {
			return teid, nil
		}
	}
	return nil, fmt.Errorf("FTEID not found in CreatedPDR")
}

// HandlePfcpAssociationSetupResponse runs synchronously inside the association send and takes no
// lock of its own: every caller holds the UPF's UpfLock across that send (see HandleAdapterPfcpRsp).
// That is what makes the associated status and the new recovery timestamp visible together, which
// the acknowledging-incarnation record restoration reads depends on. Taking the lock here instead
// deadlocks probeUpf, which already holds it.
func HandlePfcpAssociationSetupResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.AssociationSetupResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Association Setup Response")
		return
	}

	nodeIDIE := rsp.NodeID
	if nodeIDIE == nil {
		logger.PfcpLog.Errorln("pfcp association setup response has no NodeID")
		return
	}

	nodeIDStr, err := nodeIDIE.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("pfcp association setup response NodeID error: %v", err)
		return
	}

	nodeID := context.NewNodeID(nodeIDStr)

	if rsp.Cause == nil {
		logger.PfcpLog.Errorln("pfcp association setup response has no cause")
		return
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("pfcp association setup response cause error: %v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		logger.PfcpLog.Infof("handle PFCP Association Setup Response with NodeID[%s]", nodeID.ResolveNodeIdToIp().String())

		upf := context.RetrieveUPFNodeByNodeID(*nodeID)
		if upf == nil {
			logger.PfcpLog.Errorf("can not find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
			return
		}

		upf.UPFStatus = context.AssociatedSetUpSuccess
		logger.PfcpLog.Debugln("upf status updated to associated: %+v", upf.UPFStatus)
		if rsp.RecoveryTimeStamp == nil {
			logger.PfcpLog.Errorln("pfcp association setup response has no RecoveryTimeStamp")
			return
		}
		recoveryTimestamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
		if err != nil {
			logger.PfcpLog.Errorf("pfcp association setup response RecoveryTimeStamp error: %v", err)
			return
		}
		// Compared before the overwrite below, for the same reason as on the native path: once the
		// held value has been replaced the evidence of the restart is gone, and what remains is the
		// state that hides it.
		if upf.HasRestarted(recoveryTimestamp) {
			logger.PfcpLog.Warnf("PFCP Association Setup Response, upf [%v] recovery timestamp changed", upf.NodeID)
			// Lawful Interception: discard the trigger claims the restarted UPF no longer
			// holds, as the native handler does. Only one of the two handlers is active in a
			// deployment, so a remedy in the native one alone would depend on enableUPFAdapter.
			notifyPOIRestarted(upf.NodeID, upf.NodeID.ResolveNodeIdToIp().String())
			if context.OnRestart != nil {
				context.OnRestart(upf.NodeID, recoveryTimestamp)
			}
		}

		upf.RecoveryTimeStamp = context.RecoveryTimeStamp{
			RecoveryTimeStamp: recoveryTimestamp,
		}
		upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
	}
}

func HandlePfcpHeartbeatResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.HeartbeatResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Heartbeat Response")
		return
	}

	// Get NodeId from Seq:NodeId Map
	seq := rsp.Sequence()
	nodeID := FetchPfcpTxn(seq)

	if nodeID == nil {
		logger.PfcpLog.Errorf("no pending pfcp heartbeat response for sequence no: %v", seq)
		// metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, pfcpmsgtypes.PfcpMsgTypeString(msg.PfcpMessage.Header.MessageType), "In", "Failure", "invalid_seqno")
		return
	}

	logger.PfcpLog.Debugf("handle pfcp heartbeat response seq[%d] with NodeID[%v, %s]", seq, nodeID, nodeID.ResolveNodeIdToIp().String())

	upf := context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		// metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, pfcpmsgtypes.PfcpMsgTypeString(msg.PfcpMessage.Header.MessageType), "In", "Failure", "unknown_upf")
		return
	}

	if rsp.RecoveryTimeStamp == nil {
		logger.PfcpLog.Errorln("pfcp heartbeat response has no RecoveryTimeStamp")
		return
	}

	recoveryTimestamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		logger.PfcpLog.Errorf("pfcp heartbeat response RecoveryTimeStamp error: %v", err)
		return
	}

	if upf.HasRestarted(recoveryTimestamp) {
		// change UPF state to not associated so that
		// PFCP Association can be initiated again
		upf.UPFStatus = context.NotAssociated
		logger.PfcpLog.Warnf("PFCP Heartbeat Response, upf [%v] recovery timestamp changed", upf.NodeID)

		// Lawful Interception: the adapter's copy of the native handler's remedy. This UPF
		// restarted, so the LI_T3 triggers this element believes it installed there are gone
		// with its memory — and keeping the claims makes the planning path skip every triple
		// as claimed, so nothing re-installs.
		notifyPOIRestarted(upf.NodeID, upf.NodeID.ResolveNodeIdToIp().String())

		if context.OnRestart != nil {
			context.OnRestart(upf.NodeID, recoveryTimestamp)
		}
	}

	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
}

func HandlePfcpSessionEstablishmentResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.SessionEstablishmentResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Session Establishment Response")
		return
	}
	logger.PfcpLog.Infoln("in HandlePfcpSessionEstablishmentResponse")

	SEID := rsp.SEID()
	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			logger.PfcpLog.Warnln("PFCP Session Establish Response found invalid event data, response discarded")
			return
		} else {
			SEID = eventData.LSEID
		}
	}
	smContext := context.GetSMContextBySEID(SEID)
	if smContext == nil {
		logger.PfcpLog.Warnln("PFCP Session Establish Response found SM context nil, response discarded")
		return
	}
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	logger.PfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse SEID %v", SEID)
	logger.PfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse smContext %+v", smContext)

	// Get NodeId from Seq:NodeId Map
	seq := rsp.Sequence()
	nodeID := FetchPfcpTxn(seq)
	if nodeID == nil {
		logger.PfcpLog.Errorf("no pending pfcp session establishment response for sequence no: %v", seq)
		return
	}

	if rsp.UPFSEID != nil {
		NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
		pfcpSessionCtx := smContext.PFCPContext[NodeIDtoIP]
		rspUPFseid, err := rsp.UPFSEID.FSEID()
		if err != nil {
			logger.PfcpLog.Errorf("pfcp session establishment response UPFSEID error: %v", err)
			return
		}
		pfcpSessionCtx.RemoteSEID = rspUPFseid.SEID
		// Which incarnation of the node acknowledged it, so a restoration after a restart can tell a
		// session the restarted node lost from one it already holds. See AcknowledgedAtRecovery.
		if upf := context.RetrieveUPFNodeByNodeID(*nodeID); upf != nil {
			pfcpSessionCtx.AcknowledgedAtRecovery = upf.HeldRecovery()
		}
		smContext.SubPfcpLog.Infof("in HandlePfcpSessionEstablishmentResponse rsp.UPFSEID.Seid [%v] ", rspUPFseid.SEID)
	}

	// Get N3 interface UPF
	defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
	if defaultPath == nil {
		logger.PfcpLog.Errorln("failed to get default path")
		return
	}
	ANUPF := smContext.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode

	if rsp.CreatedPDR != nil {
		ueIPAddress := FindUEIPAddress(rsp.CreatedPDR)
		if ueIPAddress != nil {
			smContext.SubPfcpLog.Infof("upf provided ue ip address [%v]", ueIPAddress)
			// Release previous locally allocated UE IP-Addr
			err := smContext.ReleaseUeIpAddr()
			if err != nil {
				logger.PfcpLog.Errorf("failed to release UE IP-Addr: %+v", err)
			}

			// Update with one received from UPF
			smContext.PDUAddress.Ip = ueIPAddress
			smContext.PDUAddress.UpfProvided = true
		}

		// Store F-TEID created by UPF
		fteid, err := FindFTEID(rsp.CreatedPDR)
		if err != nil {
			logger.PfcpLog.Errorf("failed to parse TEID IE: %+v", err)
			return
		}
		logger.PfcpLog.Infof("created PDR FTEID: %+v", fteid)
		ANUPF.UpLinkTunnel.TEID = fteid.TEID
		upf := context.RetrieveUPFNodeByNodeID(*nodeID)
		if upf == nil {
			logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
			return
		}
		upf.N3Interfaces = make([]context.UPFInterfaceInfo, 0)
		n3Interface := context.UPFInterfaceInfo{}
		n3Interface.IPv4EndPointAddresses = append(n3Interface.IPv4EndPointAddresses, fteid.IPv4Address)
		upf.N3Interfaces = append(upf.N3Interfaces, n3Interface)
	}

	if rsp.NodeID == nil {
		logger.PfcpLog.Errorln("PFCP Session Establishment Response missing NodeID")
		return
	}
	rspNodeIDStr, err := rsp.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse NodeID IE: %+v", err)
		return
	}
	rspNodeID := context.NewNodeID(rspNodeIDStr)

	if ANUPF.UPF == nil {
		logger.PfcpLog.Errorln("failed to get UPF from default path")
		return
	}

	if ANUPF.UPF.NodeID.ResolveNodeIdToIp().Equal(nodeID.ResolveNodeIdToIp()) {
		if rsp.Cause == nil {
			logger.PfcpLog.Errorln("pfcp session establishment response has no cause")
			return
		}
		causeValue, err := rsp.Cause.Cause()
		if err != nil {
			logger.PfcpLog.Errorf("pfcp session establishment response cause error: %v", err)
			return
		}
		// Gated on the state, like the modification and release handlers. Restoration issues an
		// establishment without waiting on this channel, so an unconditional send here would leave a
		// stale value for whichever unrelated modification or release next waits on it.
		awaited := smContext.SMContextState == context.SmStatePfcpCreatePending
		// UPF Accept
		if causeValue == ie.CauseRequestAccepted {
			// Lawful Interception IRI-POI: the session now exists on the UPF, so its F-SEID
			// (the X2 correlation identifier) and F-TEID are known — both were set above from
			// this response. At most once per session; silent no-op unless LI is configured.
			// SMLock is held for the whole handler.
			//
			// Inside the anchor branch, as in the native handler: the record's correlation
			// identifier is the *default path's* F-SEID, so emitting it on some other UPF's
			// response would produce the one record describing the session with nothing to
			// join it to.
			notifyReportEstablishment(smContext)

			if awaited {
				smContext.SBIPFCPCommunicationChan <- context.SessionEstablishSuccess
			}
			smContext.SubPfcpLog.Infof("PFCP Session Establishment accepted")
		} else {
			if awaited {
				smContext.SBIPFCPCommunicationChan <- context.SessionEstablishFailed
			}
			smContext.SubPfcpLog.Errorf("PFCP Session Establishment rejected with cause [%v]", causeValue)
			if causeValue == ie.CauseNoEstablishedPFCPAssociation {
				SetUpfInactive(*rspNodeID)
			}
		}
	}

	// Lawful Interception CC-TF: task the CC-POI of the UPF that has just created this session.
	// The trigger's packet detection criterion is the F-SEID that response assigns, so this is
	// the earliest point it can be sent — the duplication instruction itself rode out with the
	// request.
	//
	// Outside the anchor branch above, as in the native handler, because a session can be served
	// by more than one UPF and only the anchor's response takes that branch. Inside it, an
	// additional PSA got its DUPL FAR but never its trigger, so it duplicated the target's
	// traffic into content the CC-POI could not attribute and correctly dropped. Triggering is
	// idempotent per (warrant, session, UPF).
	if establishmentAccepted(rsp) {
		// Re-derive duplication before tasking: a warrant that activated while this session was
		// being established has not been applied to its FARs by anyone, and this is the first
		// point ordered after the session exists. Under the same lock, so it cannot race the
		// rules it reads.
		notifyApplyCCAfterEstablishment(smContext)
		notifyTriggerCC(smContext)
	}
}

func HandlePfcpSessionModificationResponse(msg *udp.Message) {
	pfcpRsp, ok := msg.PfcpMessage.(*message.SessionModificationResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Session Modification Response")
		return
	}
	logger.PfcpLog.Infoln("in HandlePfcpSessionModificationResponse")

	cause := pfcpRsp.Cause
	if cause == nil {
		logger.PfcpLog.Warnln("PFCP Session Modification Response found invalid cause, response discarded")
		return
	}
	causeValue, err := cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("PFCP Session Modification Response cause error: %v", err)
		return
	}

	logger.PfcpLog.Infof("in HandlePfcpSessionModificationResponse pfcpRsp.Cause.CauseValue = [%v], accepted?? %v", causeValue, causeValue == ie.CauseRequestAccepted)

	SEID := pfcpRsp.SEID()
	logger.PfcpLog.Infof("in HandlePfcpSessionModificationResponse SEID %v", SEID)

	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			logger.PfcpLog.Warnln("PFCP Session Modification Response found invalid event data, response discarded")
			return
		} else {
			SEID = eventData.LSEID
		}
	}

	smContext := context.GetSMContextBySEID(SEID)
	logger.PfcpLog.Infof("in HandlePfcpSessionModificationResponse smContext found by SEID %v", smContext)

	// A modification this element sent for Lawful Interception, not one the session's
	// own procedures sent — the same guard the native handler applies, on the path
	// taken when enableUPFAdapter is set. sendSessionModification routes the response
	// through HandleAdapterPfcpRsp in that mode, and this handler had none: an LI
	// modification's response landing during SmStatePfcpModify cleared the pending-UPF
	// entry the subscriber's own concurrent modification was waiting on and completed
	// that procedure on an answer never sent to it. The correlation below — SEID,
	// serving UPF, procedure state — cannot tell the two apart, which is why the
	// sequence number is what answers it.
	//
	// Note that Take *consumes* the record. Before this, nothing in adapter mode consumed
	// it, so every LI-originated sequence number lingered until the age-out.
	//
	// **And the answer is read.** Keeping it out of the subscriber's procedure is one
	// obligation and discarding it was a second mistake: the Cause says whether the
	// datapath applied the duplication this element had already recorded as applied, and
	// with it discarded a refused activation was never retried — the element holding a
	// task it reports as intercepting and a datapath that declined it, with nothing left
	// to re-send and nothing reported. A refused withdrawal left duplication running while
	// the element believed it was off.
	if req, ok := lisequence.Take(pfcpRsp.Sequence()); ok {
		notifyLIModificationAnswered(req, causeValue, true)

		return
	}

	// After the interception block, as in the native handler: that block answers a
	// modification this element sent itself, keyed on the sequence number alone, and it must
	// still run when the session has since been released.
	if smContext == nil {
		logger.PfcpLog.Warnf("PFCP Session Modification Response found SM context nil for SEID %d, response discarded", SEID)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		smContext.SubPduSessLog.Infoln("PFCP Modification Response Accept")
		if smContext.SMContextState == context.SmStatePfcpModify {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Debugf("delete pending pfcp response: UPF IP [%s]", upfIP)

			if smContext.PendingUPF.IsEmpty() {
				smContext.SBIPFCPCommunicationChan <- context.SessionUpdateSuccess
			}
		}

		smContext.SubPfcpLog.Infof("PFCP Session Modification Success[%d]", SEID)
	} else {
		smContext.SubPfcpLog.Infof("PFCP Session Modification Failed[%d]", SEID)
		if smContext.SMContextState == context.SmStatePfcpModify {
			smContext.SBIPFCPCommunicationChan <- context.SessionUpdateFailed
		}
	}

	smContext.SubCtxLog.Debugln("PFCP Session Context")
	for _, ctx := range smContext.PFCPContext {
		smContext.SubCtxLog.Debugln(ctx.String())
	}
}

func HandlePfcpSessionDeletionResponse(msg *udp.Message) {
	pfcpRsp, ok := msg.PfcpMessage.(*message.SessionDeletionResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid PFCP Session Deletion Response")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Session Deletion Response")
	SEID := pfcpRsp.SEID()

	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			logger.PfcpLog.Warnln("PFCP Session Deletion Response found invalid event data, response discarded")
			return
		} else {
			SEID = eventData.LSEID
		}
	}
	smContext := context.GetSMContextBySEID(SEID)

	if smContext == nil {
		logger.PfcpLog.Warnln("PFCP Session Deletion Response found SM context nil, response discarded")
		return
	}

	cause := pfcpRsp.Cause
	if cause == nil {
		logger.PfcpLog.Warnln("PFCP Session Deletion Response found invalid cause, response discarded")
		return
	}

	causeValue, err := cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("PFCP Session Deletion Response cause error: %v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		if smContext.SMContextState == context.SmStatePfcpRelease {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Debugf("delete pending pfcp response: UPF IP [%s]", upfIP)

			if smContext.PendingUPF.IsEmpty() && !smContext.LocalPurged {
				smContext.SBIPFCPCommunicationChan <- context.SessionReleaseSuccess
			}
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Success[%d]", SEID)
	} else {
		if smContext.SMContextState == context.SmStatePfcpRelease && !smContext.LocalPurged {
			smContext.SBIPFCPCommunicationChan <- context.SessionReleaseSuccess
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Failed[%d]", SEID)
	}
}

func SetUpfInactive(nodeID context.NodeID) {
	upf := context.RetrieveUPFNodeByNodeID(nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can not find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		// metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID,
		//	pfcpmsgtypes.PfcpMsgTypeString(msgType),
		//	"In", "Failure", "unknown_upf")
		return
	}

	upf.UPFStatus = context.NotAssociated
	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0

	// Lawful Interception: this UPF has stopped answering, so what it holds is no longer
	// knowable and the claims this element keeps for it are worse than useless — they make
	// the planning path skip every triple as already claimed, and they keep this element
	// telling a POI it may not be reaching that its triggering function is present, which is
	// what disables that POI's own fail-safe.
	notifyPOIRestarted(upf.NodeID, upf.NodeID.ResolveNodeIdToIp().String())
}
