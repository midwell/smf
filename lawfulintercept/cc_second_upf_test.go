// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"

	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/lawfulintercept"
	"github.com/omec-project/smf/producer"
	"github.com/omec-project/util/li/types"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// adapterUPFs stands in for the UPF adapter: it records which UPF each session modification is
// addressed to and which FARs it updates, and accepts it.
type adapterUPFs struct {
	mu   sync.Mutex
	sent map[string][]uint32 // UPF address -> FAR IDs updated, in send order
}

func (a *adapterUPFs) RoundTrip(req *http.Request) (*http.Response, error) {
	var posted struct {
		Msg struct {
			Body []byte `json:"body"`
		} `json:"pfcpMsg"`
		UpNodeID smfctx.NodeID `json:"upNodeID"`
	}
	if err := json.NewDecoder(req.Body).Decode(&posted); err != nil {
		return nil, err
	}
	parsed, err := message.Parse(posted.Msg.Body)
	if err != nil {
		return nil, err
	}
	mod, ok := parsed.(*message.SessionModificationRequest)
	if !ok {
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(&bytes.Buffer{}), Request: req}, nil
	}

	a.mu.Lock()
	node := posted.UpNodeID.ResolveNodeIdToIp().String()
	for _, far := range mod.UpdateFAR {
		if id, err := far.FARID(); err == nil {
			a.sent[node] = append(a.sent[node], id)
		}
	}
	a.mu.Unlock()

	rsp := message.NewSessionModificationResponse(0, 0, 0, mod.Sequence(), 0, ie.NewCause(ie.CauseRequestAccepted))
	buf := make([]byte, rsp.MarshalLen())
	if err := rsp.MarshalTo(buf); err != nil {
		return nil, err
	}

	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(buf)), Request: req}, nil
}

func (a *adapterUPFs) to(node string) []uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()

	return append([]uint32(nil), a.sent[node]...)
}

// TestDuplicationSetWhileASecondUPFEstablishesReachesItWhenItAnswers covers a session served by
// two UPFs, of which the anchor has answered its establishment and the second has not. A warrant
// activating then sets duplication on both UPFs' forwarding FARs; the modification goes to the
// anchor only, because the second has no PFCP session to modify yet. When the second answers,
// its FAR, already duplicating on the SMF side and still marked RULE_UPDATE, must be sent to it.
func TestDuplicationSetWhileASecondUPFEstablishesReachesItWhenItAnswers(t *testing.T) {
	const (
		supi  = "imsi-262019876543299"
		nodeA = "10.0.9.1"
		nodeB = "10.0.9.2"
	)

	origConfig := factory.SmfConfig.Configuration
	off := false
	factory.SmfConfig.Configuration = &factory.Configuration{
		KafkaInfo:        factory.KafkaInfo{EnableKafka: &off},
		EnableUpfAdapter: true,
	}
	t.Cleanup(func() { factory.SmfConfig.Configuration = origConfig })

	upfs := &adapterUPFs{sent: map[string][]uint32{}}
	origTransport := http.DefaultTransport
	http.DefaultTransport = upfs
	t.Cleanup(func() { http.DefaultTransport = origTransport })

	calls := 0
	lawfulintercept.SetSessionModifier(func(sc *smfctx.SMContext) error {
		calls++
		return producer.ModifySessionForLI(sc)
	})
	t.Cleanup(func() { lawfulintercept.SetSessionModifier(nil) })

	sc := smfctx.NewSMContext(supi, 5)
	t.Cleanup(func() { smfctx.RemoveSMContext(sc.Ref) })

	farA := &smfctx.FAR{FARID: 1, State: smfctx.RULE_CREATE, ApplyAction: smfctx.ApplyAction{Forw: true}}
	farB := &smfctx.FAR{FARID: 2, State: smfctx.RULE_CREATE, ApplyAction: smfctx.ApplyAction{Forw: true}}
	a, b := smfctx.NewDataPathNode(), smfctx.NewDataPathNode()
	a.UPF = &smfctx.UPF{NodeID: *smfctx.NewNodeID(nodeA), Port: 8805}
	b.UPF = &smfctx.UPF{NodeID: *smfctx.NewNodeID(nodeB), Port: 8805}
	a.UpLinkTunnel.PDR["ul"] = &smfctx.PDR{PDRID: 1, FAR: farA}
	b.UpLinkTunnel.PDR["ul"] = &smfctx.PDR{PDRID: 2, FAR: farB}
	a.DownLinkTunnel.SrcEndPoint, b.UpLinkTunnel.SrcEndPoint = b, a

	sc.SMLock.Lock()
	sc.Supi = supi
	sc.Tunnel = &smfctx.UPTunnel{DataPathPool: smfctx.DataPathPool{
		1: &smfctx.DataPath{FirstDPNode: a, IsDefaultPath: true, Activated: true},
	}}
	sc.PFCPContext = map[string]*smfctx.PFCPSessionContext{
		nodeA: {NodeID: a.UPF.NodeID, LocalSEID: 0x9101, RemoteSEID: 0x9201},
		nodeB: {NodeID: b.UPF.NodeID, LocalSEID: 0x9102},
	}
	sc.SMLock.Unlock()

	activate := lawfulintercept.ActivateForTest(t, types.InterceptTask{
		XID:      "task-cc-second-upf",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543299"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	})
	activate()

	sc.SMLock.Lock()
	if !farB.ApplyAction.Dupl || farB.State != smfctx.RULE_UPDATE {
		sc.SMLock.Unlock()
		t.Fatalf("precondition: the second UPF's FAR is Dupl=%v State=%v after the activation, "+
			"want a duplication change not yet sent", farB.ApplyAction.Dupl, farB.State)
	}
	sc.SMLock.Unlock()
	if got := upfs.to(nodeA); len(got) != 1 || got[0] != farA.FARID {
		t.Fatalf("precondition: the anchor was sent FARs %v, want [%d]", got, farA.FARID)
	}
	if got := upfs.to(nodeB); len(got) != 0 {
		t.Fatalf("precondition: a UPF with no PFCP session was sent FARs %v", got)
	}
	before := calls

	// The second UPF answers its establishment.
	sc.SMLock.Lock()
	sc.PFCPContext[nodeB].RemoteSEID = 0x9202
	lawfulintercept.ApplyCCAfterEstablishment(sc)
	stateB := farB.State
	sc.SMLock.Unlock()

	if calls == before {
		t.Error("no modification was made when the second UPF answered, so it keeps the FAR " +
			"it was established with, without duplication, while the SMF records it as duplicating")
	}
	if got := upfs.to(nodeB); len(got) != 1 || got[0] != farB.FARID {
		t.Errorf("the second UPF was sent FARs %v, want [%d]", got, farB.FARID)
	}
	if stateB == smfctx.RULE_UPDATE {
		t.Error("the second UPF's FAR is still RULE_UPDATE: the duplication change was never sent")
	}
}
