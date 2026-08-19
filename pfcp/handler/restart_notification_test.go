// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package handler_test

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/pfcp/handler"
	pfcp_message "github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// restartRecorder captures the Lawful Interception restart notification this package
// raises, through the same package variable the adapter uses.
//
// The native handler calls lawfulintercept.POIRestarted directly, which cannot be observed
// from here without standing up the whole subsystem — so what these tests assert is the
// *timestamp comparison*, which is the part that was missing: the association handlers
// overwrote the recovery timestamp with no notification at all, on either path.
type restartRecorder struct {
	mu    sync.Mutex
	nodes []string
}

func (r *restartRecorder) note(node context.NodeID, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nodes = append(r.nodes, node.ResolveNodeIdToIp().String())
}

func (r *restartRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.nodes)
}

// associationConfig is the minimum configuration the association handlers dereference.
func associationConfig(t *testing.T) {
	t.Helper()

	factory.SmfConfig = factory.Config{
		Configuration: &factory.Configuration{
			KafkaInfo:        factory.KafkaInfo{EnableKafka: boolPointer(false)},
			EnableUpfAdapter: false,
		},
	}
}

// TestReAssociationIsRecognisedAsARestart is the discovery path the notification never
// reached.
//
// `POIRestarted` fired only from the heartbeat recovery-timestamp mismatch, which requires
// this element to have been successfully heartbeating the UPF all along. A UPF that goes
// away and comes back **re-associates** — that is the common case, and both association
// handlers overwrote the recovery timestamp silently. Until it was noticed, every claim in
// the trigger registry went on describing tasking that no longer exists, so the planning path
// found each triple already claimed and installed nothing: the restarted UPF holds no
// tasking, discards the copies it is told to make as untasked, and this element reports the
// interception as running.
//
// The two halves are asserted separately because each is a way of getting it wrong: a
// re-association carrying a *new* timestamp is a restart, and one carrying the timestamp this
// element already held is not — discarding claims there would withdraw nothing and re-install
// everything for no reason.
func TestReAssociationIsRecognisedAsARestart(t *testing.T) {
	associationConfig(t)

	// A node of its own per case: UPFs live in a process-wide pool keyed by NodeID, so two
	// cases sharing one would have the handler retrieve the other case's UPF and compare
	// against a timestamp that case had already moved.
	for _, tc := range []struct {
		name      string
		node      string
		restarted bool
		want      int
	}{
		{"a new recovery timestamp", "2.2.2.2", true, 1},
		{"the timestamp this element already held", "2.2.2.3", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &restartRecorder{}
			restore := handler.POIRestarted
			handler.POIRestarted = rec.note
			t.Cleanup(func() { handler.POIRestarted = restore })

			// Truncated to a second, because that is what a stored timestamp is: it came
			// from a RecoveryTimeStamp IE, whose granularity is one second. A value with
			// nanoseconds is not a state this element can be in, and comparing against one
			// would report a restart on every association.
			held := time.Now().Add(-time.Hour).Truncate(time.Second)
			upNodeID := context.NewNodeID(tc.node)
			upf := context.NewUPF(upNodeID, nil)
			upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: held}

			announced := held
			if tc.restarted {
				announced = time.Now().Truncate(time.Second)
			}

			pfcp_message.InsertPfcpTxn(7, upNodeID)
			handler.HandlePfcpAssociationSetupResponse(&udp.Message{
				RemoteAddr: &net.UDPAddr{IP: net.ParseIP(tc.node), Port: 8805},
				PfcpMessage: message.NewAssociationSetupResponse(7,
					ie.NewCause(ie.CauseRequestAccepted),
					ie.NewNodeID(tc.node, "", ""),
					ie.NewRecoveryTimeStamp(announced)),
			})

			if n := rec.count(); n != tc.want {
				t.Errorf("the restart notification fired %d times, want %d: re-association is the "+
					"common way a restart is discovered, and this path overwrote the recovery "+
					"timestamp without telling the interception subsystem", n, tc.want)
			}
			// Whatever it concluded, the timestamp is still recorded: the notification is
			// additional to the existing behaviour, not instead of it.
			if !upf.RecoveryTimeStamp.RecoveryTimeStamp.Truncate(time.Second).Equal(announced.Truncate(time.Second)) {
				t.Errorf("RecoveryTimeStamp = %v, want %v", upf.RecoveryTimeStamp.RecoveryTimeStamp, announced)
			}
		})
	}
}

// TestAnInboundAssociationIsRecognisedAsARestart is the other direction: the UPF initiates
// the association. Both handlers exist because either party may start it, and a remedy in one
// of them is a remedy whose presence depends on which end noticed first.
func TestAnInboundAssociationIsRecognisedAsARestart(t *testing.T) {
	associationConfig(t)

	rec := &restartRecorder{}
	restore := handler.POIRestarted
	handler.POIRestarted = rec.note
	t.Cleanup(func() { handler.POIRestarted = restore })

	upNodeID := context.NewNodeID("3.3.3.3")
	upf := context.NewUPF(upNodeID, nil)
	upf.RecoveryTimeStamp = context.RecoveryTimeStamp{RecoveryTimeStamp: time.Now().Add(-time.Hour)}

	handler.HandlePfcpAssociationSetupRequest(&udp.Message{
		RemoteAddr: &net.UDPAddr{IP: net.ParseIP("3.3.3.3"), Port: 8805},
		PfcpMessage: message.NewAssociationSetupRequest(9,
			ie.NewNodeID("3.3.3.3", "", ""),
			ie.NewRecoveryTimeStamp(time.Now())),
	})

	if n := rec.count(); n != 1 {
		t.Errorf("an inbound re-association raised %d restart notifications, want 1", n)
	}
}
