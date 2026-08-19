// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package upf

import (
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/lawfulintercept"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/pfcp/message"
	pfcp_message "github.com/wmnsk/go-pfcp/message"
)

const (
	maxHeartbeatRetry        = 3  // sec
	maxHeartbeatInterval     = 10 // sec
	maxUpfProbeRetryInterval = 10 // sec
)

func InitPfcpHeartbeatRequest() {
	// Iterate through all UPFs and send heartbeat to active UPFs
	for {
		time.Sleep(maxHeartbeatInterval * time.Second)
		userplane := context.SMF_Self().UserPlaneInformation
		if userplane == nil {
			continue
		}
		for _, upf := range userplane.UPFs {
			upf.UPF.UpfLock.Lock()
			if (upf.UPF.UPFStatus == context.AssociatedSetUpSuccess) && upf.UPF.NHeartBeat < maxHeartbeatRetry {
				err := message.SendHeartbeatRequest(upf.NodeID, upf.Port) // needs lock in sync rsp(adapter mode)
				if err != nil {
					logger.PfcpLog.Errorf("send pfcp heartbeat request failed: %v for UPF[%v, %v]: ", err, upf.NodeID, upf.NodeID.ResolveNodeIdToIp())
				} else {
					upf.UPF.NHeartBeat++
				}
			} else if upf.UPF.NHeartBeat == maxHeartbeatRetry {
				logger.PfcpLog.Errorf("pfcp heartbeat failure for UPF: [%v]", upf.NodeID)
				heartbeatRequest := pfcp_message.HeartbeatRequest{}
				metrics.IncrementN4MsgStats(context.SMF_Self().NfInstanceID, heartbeatRequest.MessageTypeName(), "Out", "Failure", "Timeout")
				upf.UPF.UPFStatus = context.NotAssociated

				// Lawful Interception: this UPF has stopped answering, so what it holds is
				// no longer knowable — and the claims this element keeps for it are worse
				// than useless. They make `plan` skip every triple as already claimed, so
				// nothing re-installs when the UPF comes back, and they keep
				// `keepaliveDue` true, so this element goes on telling a POI it may not be
				// reaching that its triggering function is present — which is precisely
				// what disables that POI's own fail-safe.
				//
				// Discarding them is the same conclusion the heartbeat mismatch and the
				// re-association paths reach, by the route that reaches it first: a claim
				// that cannot be true must not be treated as one.
				//
				// This does not restore the subscriber's sessions. Those are the upstream
				// `// TODO: Session cleanup required` on the association paths, which is
				// larger and separate; what is in scope is that the interception
				// bookkeeping stops being the reason re-tasking cannot happen.
				lawfulintercept.POIRestarted(upf.NodeID, upf.NodeID.ResolveNodeIdToIp().String())
			}

			upf.UPF.UpfLock.Unlock()
		}
	}
}

func ProbeInactiveUpfs() {
	// Iterate through all UPFs and send PFCP request to inactive UPFs
	for {
		time.Sleep(maxUpfProbeRetryInterval * time.Second)
		upfs := context.SMF_Self().UserPlaneInformation
		if upfs == nil {
			continue
		}
		for _, upf := range upfs.UPFs {
			upf.UPF.UpfLock.Lock()
			if upf.UPF.UPFStatus == context.NotAssociated {
				err := message.SendPfcpAssociationSetupRequest(upf.NodeID, upf.Port)
				if err != nil {
					logger.PfcpLog.Errorf("send pfcp association setup request failed: %v ", err)
				}
			}
			upf.UPF.UpfLock.Unlock()
		}
	}
}
