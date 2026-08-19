// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"fmt"
	"net"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/consumer"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/lawfulintercept"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/pfcp/ies"
	"github.com/omec-project/smf/pfcp/lisequence"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/omec-project/smf/producer"
	"github.com/omec-project/smf/util"
	mi "github.com/omec-project/util/metricinfo"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

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

// POIRestarted is the Lawful Interception restart notification this package raises: a
// triggered point of interception has restarted, so the tasking this element believes it
// holds there must be discarded and re-installed.
//
// Reached through a package variable so a test can observe *which* of this package's paths
// raise it, which is the whole of what was wrong — it fired only from the heartbeat
// recovery-timestamp mismatch, while both association handlers overwrote the recovery
// timestamp silently and re-association is the common way a restart is discovered. Without a
// seam a path that stopped raising it would look exactly like a path that raises it.
//
// Production behaviour is unchanged: it is the same function.
var POIRestarted = lawfulintercept.POIRestarted

// LIModificationAnswered is the Lawful Interception hook carrying the outcome of a
// modification the interception subsystem sent. Reached through a package variable for the
// reason POIRestarted is: so a test can observe that this path raises it.
var LIModificationAnswered = lawfulintercept.ModificationAnswered

// liResponseCause reads the Cause of a session modification response, reporting whether one
// could be read at all.
//
// An answer with no readable Cause is not an acceptance. It says the element does not know
// what the datapath did, which is the same state as silence — and the element must treat
// "do not know" as "not applied", because over-applying duplication is visible to the CC-POI
// as content it can attribute while under-applying it is silent.
func liResponseCause(rsp *message.SessionModificationResponse) (uint8, bool) {
	if rsp.Cause == nil {
		return 0, false
	}
	cause, err := rsp.Cause.Cause()
	if err != nil {
		return 0, false
	}

	return cause, true
}

func HandlePfcpHeartbeatRequest(msg *udp.Message) {
	_, ok := msg.PfcpMessage.(*message.HeartbeatRequest)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for heartbeat request")
		return
	}
	logger.PfcpLog.Infof("handle PFCP Heartbeat Request")
	err := pfcp_message.SendHeartbeatResponse(msg.RemoteAddr, msg.PfcpMessage.Sequence())
	if err != nil {
		logger.PfcpLog.Errorf("failed to send PFCP Heartbeat Response: %+v", err)
	}
}

func HandlePfcpHeartbeatResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.HeartbeatResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for heartbeat response")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Heartbeat Response")

	// Get NodeId from Seq:NodeId Map
	seq := rsp.Sequence()
	nodeID := pfcp_message.FetchPfcpTxn(seq)

	if nodeID == nil {
		logger.PfcpLog.Errorf("no pending pfcp heartbeat response for sequence no: %v", seq)
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, rsp.MessageTypeName(), "In", "Failure", "invalid_seqno")
		return
	}

	logger.PfcpLog.Debugf("handle pfcp heartbeat response seq[%d] with NodeID[%v, %s]", seq, nodeID, nodeID.ResolveNodeIdToIp().String())

	upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can not find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, rsp.MessageTypeName(), "In", "Failure", "unknown_upf")
		return
	}
	upf.UpfLock.Lock()
	defer upf.UpfLock.Unlock()

	rspRecoveryTimeStamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse RecoveryTimeStamp: %+v", err)
		return
	}

	if upf.RecoveryTimeStamp.RecoveryTimeStamp.IsZero() {
		upf.RecoveryTimeStamp = smf_context.RecoveryTimeStamp{
			RecoveryTimeStamp: rspRecoveryTimeStamp,
		}
	} else if rspRecoveryTimeStamp != upf.RecoveryTimeStamp.RecoveryTimeStamp {
		// change UPF state to not associated so that
		// PFCP Association can be initiated again
		upf.UPFStatus = smf_context.NotAssociated
		logger.PfcpLog.Warnf("PFCP Heartbeat Response, upf [%v] recovery timestamp changed, previous [%v], new [%v] ", upf.NodeID, upf.RecoveryTimeStamp, *rsp.RecoveryTimeStamp)

		// Lawful Interception: this UPF restarted, so the LI_T3 triggers this element
		// believes it installed there are gone with its memory. Discard the record, or
		// the planning path finds every triple already claimed and installs nothing —
		// the restarted UPF holding no tasking, discarding the copies it is told to
		// make as untasked, while this element reports the interception as running.
		//
		// The node identity travels with its address, because the registry is keyed by
		// the configured node name and only the registry can match one to the other.
		//
		// This does not address the TODO below, and is not a step toward it: the
		// subscriber's PFCP sessions are lost on this path too, which is larger and
		// separate. What it does is stop the interception bookkeeping from being the
		// reason re-tasking cannot happen once that TODO is addressed.
		POIRestarted(upf.NodeID, upf.NodeID.ResolveNodeIdToIp().String())

		// TODO: Session cleanup required and updated to AMF/PCF
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, rsp.MessageTypeName(), "In", "Failure", "RecoveryTimeStamp_mismatch")
	}

	if *factory.SmfConfig.Configuration.KafkaInfo.EnableKafka {
		// Send Metric event
		upfStatus := mi.MetricEvent{
			EventType: mi.CNfStatusEvt,
			NfStatusData: mi.CNfStatus{
				NfType:   mi.NfTypeUPF,
				NfStatus: mi.NfStatusConnected, NfName: string(upf.NodeID.NodeIdValue),
			},
		}
		err := metrics.StatWriter.PublishNfStatusEvent(upfStatus)
		if err != nil {
			logger.PfcpLog.Errorf("failed to publish NfStatusEvent: %+v", err)
		}
	}

	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
}

func SetUpfInactive(nodeID smf_context.NodeID, msgTypeName string) {
	upf := smf_context.RetrieveUPFNodeByNodeID(nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can not find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, msgTypeName, "In", "Failure", "unknown_upf")
		return
	}

	upf.UpfLock.Lock()
	defer upf.UpfLock.Unlock()
	upf.UPFStatus = smf_context.NotAssociated
	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0
}

func HandlePfcpPfdManagementRequest(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP PFD Management Request handling is not implemented")
}

func HandlePfcpPfdManagementResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP PFD Management Response handling is not implemented")
}

func HandlePfcpAssociationSetupRequest(msg *udp.Message) {
	req, ok := msg.PfcpMessage.(*message.AssociationSetupRequest)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for association setup request")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Association Setup Request")

	nodeIDIE := req.NodeID
	if nodeIDIE == nil {
		logger.PfcpLog.Errorln("pfcp association needs NodeID")
		return
	}

	nodeIDStr, err := req.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse NodeID IE: %+v", err)
		return
	}

	logger.PfcpLog.Infof("handle PFCP Association Setup Request with NodeID[%s]", nodeIDStr)

	nodeID := smf_context.NewNodeID(nodeIDStr)

	recoveryTimestamp, err := req.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse RecoveryTimeStamp: %+v", err)
		return
	}

	upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can not find UPF[%s]", nodeIDStr)
		return
	}

	upf.UpfLock.Lock()
	defer upf.UpfLock.Unlock()

	// Lawful Interception: **re-association is the common way a restart is discovered**, and
	// it was the one path that overwrote the recovery timestamp without saying so. The
	// heartbeat mismatch only fires for a UPF this element was still successfully
	// heartbeating; a UPF that went away and came back re-associates, and until now that
	// left every claim in the trigger registry pointing at a POI holding no tasking. The
	// planning path then found each triple already claimed and installed nothing.
	//
	// Compared before the overwrite, and only where it changed: an association from a UPF
	// whose timestamp is the one this element already held is a re-association without a
	// restart, and discarding claims there would withdraw nothing and re-install everything
	// for no reason.
	//
	// As at the heartbeat site, this does not address the TODO on that path: the subscriber's
	// PFCP sessions are lost with the UPF's memory either way, which is larger and separate.
	if restarted := !upf.RecoveryTimeStamp.RecoveryTimeStamp.IsZero() &&
		upf.RecoveryTimeStamp.RecoveryTimeStamp != recoveryTimestamp; restarted {
		POIRestarted(upf.NodeID, upf.NodeID.ResolveNodeIdToIp().String())
	}

	upf.RecoveryTimeStamp = smf_context.RecoveryTimeStamp{
		RecoveryTimeStamp: recoveryTimestamp,
	}
	upf.NHeartBeat = 0 // reset Heartbeat attempt to 0

	// Response with PFCP Association Setup Response
	err = pfcp_message.SendPfcpAssociationSetupResponse(*nodeID, ie.CauseRequestAccepted, upf.Port)
	if err != nil {
		logger.PfcpLog.Errorf("failed to send PFCP Association Setup Response: %+v", err)
	}
}

func HandlePfcpAssociationSetupResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.AssociationSetupResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for association setup response")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Association Setup Response")

	nodeIDIE := rsp.NodeID
	logger.PfcpLog.Debugf("handle PFCP Association Setup Response with NodeID[%+v]", nodeIDIE)

	if nodeIDIE == nil {
		logger.PfcpLog.Errorln("pfcp association setup response has no NodeID")
		return
	}

	nodeIDStr, err := rsp.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse NodeID IE: %+v", err)
		return
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse Cause IE: %+v", err)
		return
	}
	logger.PfcpLog.Debugf("handle PFCP Association Setup Response with Cause[%v]", causeValue)
	if causeValue == ie.CauseRequestAccepted {
		// Get NodeId from Seq:NodeId Map
		seq := rsp.Sequence()
		nodeID := pfcp_message.FetchPfcpTxn(seq)

		if nodeID == nil {
			logger.PfcpLog.Errorf("no pending pfcp Assoc req for sequence no: %v", seq)
			metrics.IncrementN4MsgStats(smf_context.SMF_Self().NfInstanceID, rsp.MessageTypeName(), "In", "Failure", "invalid_seqno")
			return
		}

		upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
		logger.PfcpLog.Debugf("handle PFCP Association Setup Response with UPF[%+v]", upf)
		if upf == nil {
			logger.PfcpLog.Errorf("cannot find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
			return
		}

		upf.UpfLock.Lock()
		defer upf.UpfLock.Unlock()

		upf.UPFStatus = smf_context.AssociatedSetUpSuccess
		logger.PfcpLog.Infof("upf status updated to %v for NodeID[%s]", upf.UPFStatus, nodeIDStr)

		recoveryTimestamp, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
		if err != nil {
			logger.PfcpLog.Errorf("failed to parse RecoveryTimeStamp: %+v", err)
			return
		}

		// Lawful Interception: the other half of re-association — this element initiated it,
		// which is what ProbeInactiveUpfs does for every UPF it has marked NotAssociated. See
		// the request handler above for why this path matters and why the comparison is made
		// before the overwrite.
		if restarted := !upf.RecoveryTimeStamp.RecoveryTimeStamp.IsZero() &&
			upf.RecoveryTimeStamp.RecoveryTimeStamp != recoveryTimestamp; restarted {
			POIRestarted(upf.NodeID, upf.NodeID.ResolveNodeIdToIp().String())
		}

		upf.RecoveryTimeStamp = smf_context.RecoveryTimeStamp{
			RecoveryTimeStamp: recoveryTimestamp,
		}
		upf.NHeartBeat = 0

		if *factory.SmfConfig.Configuration.KafkaInfo.EnableKafka {
			upfStatus := mi.MetricEvent{
				EventType: mi.CNfStatusEvt,
				NfStatusData: mi.CNfStatus{
					NfType:   mi.NfTypeUPF,
					NfStatus: mi.NfStatusConnected,
					NfName:   string(upf.NodeID.NodeIdValue),
				},
			}
			err := metrics.StatWriter.PublishNfStatusEvent(upfStatus)
			if err != nil {
				logger.PfcpLog.Errorf("failed to publish NfStatusEvent: %+v", err)
			}
		}

		if rsp.UPFunctionFeatures != nil {
			UPFunctionFeatures, err := ies.UnmarshalUserPlaneFunctionFeatures(rsp.UPFunctionFeatures.Payload)
			if err != nil {
				logger.PfcpLog.Warnf("failed to get UPFunctionFeatures: %+v", err)
				return
			}
			logger.PfcpLog.Debugf("handle PFCP Association Setup success Response, received UPFunctionFeatures= %v ", UPFunctionFeatures)
			upf.UPFunctionFeatures = UPFunctionFeatures
		}
	}
}

func HandlePfcpAssociationUpdateRequest(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Association Update Request handling is not implemented")
}

func HandlePfcpAssociationUpdateResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Association Update Response handling is not implemented")
}

func HandlePfcpAssociationReleaseRequest(msg *udp.Message) {
	pfcpMsg, ok := msg.PfcpMessage.(*message.AssociationReleaseRequest)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for association release request")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Association Release Request")

	nodeIDIE := pfcpMsg.NodeID
	if nodeIDIE == nil {
		logger.PfcpLog.Errorln("pfcp association release needs NodeID")
		return
	}

	nodeIDStr, err := pfcpMsg.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse NodeID IE: %+v", err)
		return
	}

	nodeID := smf_context.NewNodeID(nodeIDStr)

	upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can not find UPF[%s]", nodeIDStr)
		return
	}
	smf_context.RemoveUPFNodeByNodeID(*nodeID)
	err = pfcp_message.SendPfcpAssociationReleaseResponse(*nodeID, ie.CauseRequestAccepted, upf.Port)
	if err != nil {
		logger.PfcpLog.Errorf("failed to send PFCP Association Release Response: %+v", err)
	}
}

func HandlePfcpAssociationReleaseResponse(msg *udp.Message) {
	pfcpMsg, ok := msg.PfcpMessage.(*message.AssociationReleaseResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for association release response")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Association Release Response")
	if pfcpMsg.Cause == nil {
		logger.PfcpLog.Errorln("pfcp association release response needs Cause")
		return
	}
	causeValue, err := pfcpMsg.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse Cause IE: %+v", err)
		return
	}
	if causeValue == ie.CauseRequestAccepted {
		nodeIDIE := pfcpMsg.NodeID
		if nodeIDIE == nil {
			logger.PfcpLog.Errorln("pfcp association release needs NodeID")
			return
		}
		nodeIDStr, err := pfcpMsg.NodeID.NodeID()
		if err != nil {
			logger.PfcpLog.Errorf("failed to parse NodeID IE: %+v", err)
			return
		}
		nodeID := smf_context.NewNodeID(nodeIDStr)
		smf_context.RemoveUPFNodeByNodeID(*nodeID)
	}
}

func HandlePfcpVersionNotSupportedResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Version Not Support Response handling is not implemented")
}

func HandlePfcpNodeReportRequest(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Node Report Request handling is not implemented")
}

func HandlePfcpNodeReportResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Node Report Response handling is not implemented")
}

func HandlePfcpSessionSetDeletionRequest(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Session Set Deletion Request handling is not implemented")
}

func HandlePfcpSessionSetDeletionResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Session Set Deletion Response handling is not implemented")
}

// establishmentAccepted reports whether a Session Establishment Response says the
// UPF created the session. The anchor branch of the handler parses the cause for
// its own purposes; this answers the same question for the UPFs that branch does
// not cover, without disturbing it.
func establishmentAccepted(rsp *message.SessionEstablishmentResponse) bool {
	if rsp.Cause == nil {
		return false
	}
	cause, err := rsp.Cause.Cause()
	return err == nil && cause == ie.CauseRequestAccepted
}

func HandlePfcpSessionEstablishmentResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.SessionEstablishmentResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for session establishment response")
		return
	}
	logger.PfcpLog.Infof("handle PFCP Session Establishment Response")
	SEID := rsp.SEID()
	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			logger.PfcpLog.Warnln("PFCP Session Establish Response found invalid event data, response discarded")
			return
		} else {
			SEID = eventData.LSEID
		}
	}
	smContext := smf_context.GetSMContextBySEID(SEID)
	if smContext == nil {
		logger.PfcpLog.Errorf("failed to find SMContext for SEID[%d]", SEID)
		return
	}
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	// If Tunnel is nil (e.g. a stale Establishment Response arrives after
	// releaseTunnel nilled it), discard the response. Consume any pending
	// txn entry on this path too so it can't be leaked if reached without
	// having been deleted by the original response processing.
	if smContext.Tunnel == nil {
		pfcp_message.FetchPfcpTxn(rsp.Sequence())
		smContext.SubPfcpLog.Errorln("HandlePfcpSessionEstablishmentResponse: Tunnel is nil, ignoring response")
		return
	}

	// Get NodeId from Seq:NodeId Map
	seq := rsp.Sequence()
	nodeID := pfcp_message.FetchPfcpTxn(seq)
	if nodeID == nil {
		logger.PfcpLog.Errorf("no pending pfcp response for sequence no: %v", seq)
		return
	}

	if rsp.UPFSEID != nil {
		// NodeIDtoIP := rsp.NodeID.ResolveNodeIdToIp().String()
		NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
		pfcpSessionCtx := smContext.PFCPContext[NodeIDtoIP]
		rspUPFseid, err := rsp.UPFSEID.FSEID()
		if err != nil {
			logger.PfcpLog.Errorf("failed to parse FSEID IE: %+v", err)
			return
		}
		pfcpSessionCtx.RemoteSEID = rspUPFseid.SEID
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
		upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
		if upf == nil {
			logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
			return
		}
		n3Interface := smf_context.UPFInterfaceInfo{}
		n3Interface.IPv4EndPointAddresses = append(n3Interface.IPv4EndPointAddresses, fteid.IPv4Address)
		upf.UpfLock.Lock()
		upf.N3Interfaces = make([]smf_context.UPFInterfaceInfo, 0)
		upf.N3Interfaces = append(upf.N3Interfaces, n3Interface)
		upf.UpfLock.Unlock()
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
	rspNodeID := smf_context.NewNodeID(rspNodeIDStr)

	if ANUPF.UPF == nil {
		logger.PfcpLog.Errorln("failed to get UPF from default path")
		return
	}

	if ANUPF.UPF.NodeID.ResolveNodeIdToIp().Equal(nodeID.ResolveNodeIdToIp()) {
		// UPF Accept
		if rsp.Cause == nil {
			logger.PfcpLog.Errorln("PFCP Session Establishment Response missing Cause")
			return
		}
		causeValue, err := rsp.Cause.Cause()
		if err != nil {
			logger.PfcpLog.Errorf("failed to parse Cause IE: %+v", err)
			return
		}
		if causeValue == ie.CauseRequestAccepted {
			// Lawful Interception IRI-POI: the session now exists on the UPF, so its
			// F-SEID (the X2 correlation identifier) and F-TEID are known — both were
			// set above from this response. Emitting here rather than when the SBI
			// create returns is what makes the record joinable to the session's
			// content. At most once per session; silent no-op unless LI
			// is configured. SMLock is held for the whole handler.
			//
			// This one stays inside the anchor branch, unlike the CC trigger below:
			// the record's correlation identifier is the *default path's* F-SEID, so
			// emitting it on some other UPF's response would produce the one record
			// describing the session with nothing to join it to.
			lawfulintercept.ReportEstablishment(smContext)

			smContext.SBIPFCPCommunicationChan <- smf_context.SessionEstablishSuccess
			smContext.SubPfcpLog.Infoln("PFCP Session Establishment accepted")
		} else {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionEstablishFailed
			smContext.SubPfcpLog.Errorf("PFCP Session Establishment rejected with cause [%v]", causeValue)
			if causeValue == ie.CauseNoEstablishedPFCPAssociation {
				SetUpfInactive(*rspNodeID, msg.PfcpMessage.MessageTypeName())
			}
		}
	}

	// Lawful Interception CC-TF: task the CC-POI of the UPF that has just created
	// this session. The trigger's packet detection criterion is the F-SEID that
	// response assigns, so this is the earliest point it can be sent — the
	// duplication instruction itself rode out with the request.
	//
	// It sits outside the anchor branch above because a session can be served by
	// more than one UPF, and only the anchor's response takes that branch. Inside
	// it, an additional PSA — a ULCL branch, or a second node of a preconfigured
	// path whose response lands after the anchor's — got its DUPL FAR but never its
	// trigger, so it duplicated the target's traffic into content the CC-POI could
	// not attribute and correctly dropped. Triggering is idempotent per (warrant,
	// session, UPF), so the repeated calls cost a lookup. The X1 exchange runs off
	// this goroutine.
	if establishmentAccepted(rsp) {
		// Re-derive duplication before tasking. The X1 scan leaves a session whose
		// PFCP session does not exist yet to this path, so a warrant that activated
		// while this session was being established has not been applied to its FARs
		// by anyone — and this is the first point ordered after the session exists.
		// Ordinarily nothing has changed since the request went out and this sends
		// nothing. Under the same lock, so it cannot race the rules it reads.
		lawfulintercept.ApplyCCAfterEstablishment(smContext)
		lawfulintercept.TriggerCC(smContext)
	}

	if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
		if smContext.BPManager.BPStatus == smf_context.AddingPSA {
			smContext.SubPfcpLog.Infoln("keep Adding PSAndULCL")
			producer.AddPDUSessionAnchorAndULCL(smContext, *rspNodeID)
			smContext.BPManager.BPStatus = smf_context.AddingPSA
		}
	}
}

func HandlePfcpSessionModificationResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.SessionModificationResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for session establishment response")
		return
	}

	logger.PfcpLog.Infoln("handle PFCP Session Modification Response")

	SEID := rsp.SEID()

	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			logger.PfcpLog.Warnln("PFCP Session Modification Response found invalid event data, response discarded")
			return
		} else {
			SEID = eventData.LSEID
		}
	}
	smContext := smf_context.GetSMContextBySEID(SEID)

	logger.PfcpLog.Infoln("in HandlePfcpSessionModificationResponse")

	// A modification this element sent for Lawful Interception, not one the
	// session's own procedures sent. The correlation below — SEID, serving UPF,
	// procedure state — cannot tell the two apart, so without this the LI answer
	// clears the pending entry a concurrent subscriber modification is waiting on
	// and completes that procedure on an answer never sent to it.
	//
	// **Keeping it out of that procedure is one obligation; discarding it was a second
	// mistake.** The guard returned without reading the Cause, so the answer to this
	// element's own modification was thrown away — and with it, a refused activation was
	// never retried: the element held a task it reported as intercepting and a datapath
	// that had declined it, with nothing left to re-send (the send itself cleared the
	// RULE_UPDATE marker) and nothing reported. A refused withdrawal left duplication
	// running while the element believed it was off.
	if req, ok := lisequence.Take(rsp.Sequence()); ok {
		cause, answered := liResponseCause(rsp)
		LIModificationAnswered(req, cause, answered)

		return
	}

	if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
		if smContext.BPManager.BPStatus == smf_context.AddingPSA {
			smContext.SubPfcpLog.Infoln("keep Adding PSAAndULCL")

			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			producer.AddPDUSessionAnchorAndULCL(smContext, upfNodeID)
		}
	}

	if rsp.Cause == nil {
		logger.PfcpLog.Errorln("PFCP Session Modification Response missing Cause")
		return
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse Cause IE: %+v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		smContext.SubPduSessLog.Infoln("PFCP Modification Response Accept")
		if smContext.SMContextState == smf_context.SmStatePfcpModify {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Debugf("delete pending pfcp response: UPF IP [%s]", upfIP)

			if smContext.PendingUPF.IsEmpty() {
				smContext.SBIPFCPCommunicationChan <- smf_context.SessionUpdateSuccess
			}

			if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
				if smContext.BPManager.BPStatus == smf_context.UnInitialized {
					smContext.SubPfcpLog.Infoln("add PSAAndULCL")
					upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
					producer.AddPDUSessionAnchorAndULCL(smContext, upfNodeID)
					smContext.BPManager.BPStatus = smf_context.AddingPSA
				}
			}
		}

		smContext.SubPfcpLog.Infof("PFCP Session Modification Success[%d]", SEID)
	} else {
		smContext.SubPfcpLog.Infof("PFCP Session Modification Failed[%d]", SEID)
		if smContext.SMContextState == smf_context.SmStatePfcpModify {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionUpdateFailed
		}
	}

	smContext.SubCtxLog.Debugln("PFCP Session Context")
	for _, ctx := range smContext.PFCPContext {
		smContext.SubCtxLog.Debugln(ctx.String())
	}
}

func HandlePfcpSessionDeletionResponse(msg *udp.Message) {
	rsp, ok := msg.PfcpMessage.(*message.SessionDeletionResponse)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for session deletion response")
		return
	}
	logger.PfcpLog.Infoln("handle PFCP Session Deletion Response")
	SEID := rsp.SEID()

	if SEID == 0 {
		if eventData, ok := msg.EventData.(udp.PfcpEventData); !ok {
			logger.PfcpLog.Warnln("PFCP Session Deletion Response found invalid event data, response discarded")
			return
		} else {
			SEID = eventData.LSEID
		}
	}
	smContext := smf_context.GetSMContextBySEID(SEID)

	if smContext == nil {
		logger.PfcpLog.Warnln("PFCP Session Deletion Response found SM context nil, response discarded")
		return
		// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
	}

	if rsp.Cause == nil {
		logger.PfcpLog.Errorln("PFCP Session Deletion Response missing Cause")
		return
	}

	causeValue, err := rsp.Cause.Cause()
	if err != nil {
		logger.PfcpLog.Errorf("failed to parse Cause IE: %+v", err)
		return
	}

	if causeValue == ie.CauseRequestAccepted {
		if smContext.SMContextState == smf_context.SmStatePfcpRelease {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			smContext.SubPduSessLog.Debugf("delete pending pfcp response: UPF IP [%s]", upfIP)

			if smContext.PendingUPF.IsEmpty() && !smContext.LocalPurged {
				smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess
			}
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Success[%d]", SEID)
	} else {
		if smContext.SMContextState == smf_context.SmStatePfcpRelease && !smContext.LocalPurged {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess
		}
		smContext.SubPfcpLog.Infof("PFCP Session Deletion Failed[%d]", SEID)
	}
}

func HandlePfcpSessionReportRequest(msg *udp.Message) {
	req, ok := msg.PfcpMessage.(*message.SessionReportRequest)
	if !ok {
		logger.PfcpLog.Errorln("invalid message type for session report request")
		return
	}

	logger.PfcpLog.Infoln("handle PFCP Session Report Request")

	SEID := req.SEID()
	smContext := smf_context.GetSMContextBySEID(SEID)
	seqFromUPF := req.Sequence()

	var cause uint8
	var pfcpSRflag smf_context.PFCPSRRspFlags

	if smContext == nil {
		logger.PfcpLog.Warnln("PFCP Session Report Request Found SM Context NULL, Request Rejected")
		cause = ie.CauseRequestRejected

		// Rejecting buffering at UPF since not able to process Session Report Request
		pfcpSRflag.Drobu = true
		// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
		err := pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, pfcpSRflag, seqFromUPF, SEID)
		if err != nil {
			logger.PfcpLog.Errorf("failed to send PFCP Session Report Response: %+v", err)
		}
		return
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	if smContext.UpCnxState == models.UPCNXSTATE_DEACTIVATED {
		if req.ReportType.HasDLDR() {
			downlinkServiceInfo, err := req.DownlinkDataReport.DownlinkDataServiceInformation()
			if err != nil {
				logger.PfcpLog.Warnln("DownlinkDataServiceInformation not found in DownlinkDataReport")
			}

			if downlinkServiceInfo != nil {
				smContext.SubPfcpLog.Warnln("PFCP Session Report Request DownlinkDataServiceInformation handling is not implemented")
			}

			n1n2Request := models.NewN1N2MessageTransferRequest()
			defer util.CleanupMultipartTempFiles(n1n2Request)
			cause = ie.CauseRequestRejected
			pfcpSRflag.Drobu = true

			// TS 23.502 4.2.3.3 3a. Send Namf_Communication_N1N2MessageTransfer Request, SMF->AMF
			n2SmBuf, err := smf_context.BuildPDUSessionResourceSetupRequestTransfer(smContext)
			if err != nil {
				smContext.SubPduSessLog.Errorln("build PDU Session Resource Setup Request Transfer failed:", err)
			} else {
				tmpFile, fileErr := util.CreatePayloadTempFile(n2SmBuf)
				if fileErr != nil {
					smContext.SubPduSessLog.Errorf("failed to create temp file: %v", fileErr)
				} else {
					n1n2Request.SetBinaryDataN2Information(tmpFile)
				}
			}

			if n1n2Request.GetBinaryDataN2Information() != nil {
				// n1n2FailureTxfNotifURI to be added in n1n2 request transfer.
				// It is used as path by AMF to send failure notification message towards SMF
				n1n2FailureTxfNotifURI := "/nsmf-callback/sm-n1n2failnotify/"
				n1n2FailureTxfNotifURI += smContext.Ref

				n2InfoContent := models.NewN2InfoContent(models.RefToBinaryData{ContentId: "N2SmInformation"})
				n2InfoContent.SetNgapIeType(models.NGAPIETYPE_PDU_RES_SETUP_REQ)
				smInfo := models.NewN2SmInformation(smContext.PDUSessionID)
				smInfo.SetN2InfoContent(*n2InfoContent)
				if smContext.Snssai != nil {
					smInfo.SetSNssai(*smContext.Snssai)
				}
				n2InfoContainer := models.NewN2InfoContainer(models.N2INFORMATIONCLASS_SM)
				n2InfoContainer.SetSmInfo(*smInfo)

				// Temporarily assign SMF itself, TODO: TS 23.502 4.2.3.3 5. Namf_Communication_N1N2TransferFailureNotification
				jsonData := models.NewN1N2MessageTransferReqData()
				jsonData.SetPduSessionId(smContext.PDUSessionID)
				jsonData.SetSkipInd(false)
				jsonData.SetN1n2FailureTxfNotifURI(fmt.Sprintf("%s://%s:%d%s",
					smf_context.SMF_Self().URIScheme,
					smf_context.SMF_Self().RegisterIPv4,
					smf_context.SMF_Self().SBIPort,
					n1n2FailureTxfNotifURI))
				jsonData.SetN2InfoContainer(*n2InfoContainer)
				n1n2Request.SetJsonData(*jsonData)

				rspData, n1n2Err := consumer.SendN1N2TransferWithRediscovery(context.Background(), smContext, n1n2Request)
				if n1n2Err != nil {
					smContext.SubPfcpLog.Warnf("send N1N2Transfer failed: %v", n1n2Err)
				}
				if n1n2Err == nil && rspData != nil && rspData.GetCause() == models.N1N2MESSAGETRANSFERCAUSE_ATTEMPTING_TO_REACH_UE {
					smContext.SubPfcpLog.Infof("receive %v, AMF is able to page the UE", rspData.GetCause())

					pfcpSRflag.Drobu = false
					cause = ie.CauseRequestAccepted
				}
				if n1n2Err == nil && rspData != nil && rspData.GetCause() == models.N1N2MESSAGETRANSFERCAUSE_UE_NOT_RESPONDING {
					smContext.SubPfcpLog.Infof("receive %v, UE is not responding to N1N2 transfer message", rspData.GetCause())
					// TODO: TS 23.502 4.2.3.3 3c. Failure indication
				}
			} else {
				smContext.SubPfcpLog.Warnln("skipping N1N2 transfer because N2 SM information is unavailable")
			}

			// Sending Session Report Response to UPF.
			smContext.SubPfcpLog.Infof("sending Session Report to UPF with Cause %v", cause)
			err = pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, pfcpSRflag, seqFromUPF, SEID)
			if err != nil {
				logger.PfcpLog.Errorf("failed to send PFCP Session Report Response: %+v", err)
			}
		}
	}

	// TS 23.502 4.2.3.3 2b. Send Data Notification Ack, SMF->UPF
	//	cause.CauseValue = ie.CauseRequestAccepted
	// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
	// pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, seqFromUPF, SEID)
}

func HandlePfcpSessionReportResponse(msg *udp.Message) {
	logger.PfcpLog.Warnln("PFCP Session Report Response handling is not implemented")
}
