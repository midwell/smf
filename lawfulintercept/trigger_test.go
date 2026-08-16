// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	smfctx "github.com/omec-project/smf/context"
)

// upfNode parses a UPF's N4 node identity the way the session path carries it —
// unresolved, so a test can distinguish matching by identity from matching by
// address (see matchEndpoint).
func upfNode(s string) smfctx.NodeID { return *smfctx.NewNodeID(s) }

// wrongNE is an element identifier this SMF does not address, which is how a POI
// is made to answer correctly under a name the requester did not ask for.
const wrongNE = "upf-2"

// mustRegistry builds a registry from a configuration the test knows is valid.
// Construction only fails on an ambiguous configuration, which the tests that care
// about that assert on explicitly.
func mustRegistry(cfg Config) *triggerRegistry {
	reg, err := newTriggerRegistry(cfg, nil, nil)
	if err != nil {
		panic(err)
	}

	return reg
}

// fakePOI is a triggered CC-POI: it records the X1 requests a CC-TF sends it and
// answers as a conformant NE would. It lets the trigger path be exercised without
// a UPF or a PKI, since what matters here is what the CC-TF sends and how it
// reacts to the answer.
type fakePOI struct {
	mu       sync.Mutex
	bodies   []string
	refuse   bool // answer every request with an error
	srv      *httptest.Server
	requests int
	// refuseUntilProvisioned models a POI that has restarted: it refuses a trigger
	// naming a destination it does not hold, and accepts once one is created again.
	refuseUntilProvisioned bool
	provisioned            bool
	// holds is the tasking this POI reports when asked, which is how a restarted
	// triggering function discovers what it left behind.
	holds []string
	// detailsFail makes the POI refuse to say what it holds, which is the failure
	// reconciliation has to survive — an X1 endpoint that is not up yet.
	detailsFail bool
	// unhealthy maps an XID to the provisioningStatus this POI reports for it.
	// Anything other than "complete" means the trigger is not actually running,
	// which the triggering function can only learn from this answer.
	unhealthy map[string]string
	// misname makes this POI answer under a different NE identifier while otherwise
	// behaving perfectly. It models the two things the response binding exists for
	// and cannot tell apart: an endpoint a misroute put in the path, and a POI whose
	// configured identity does not match the one this SMF was told to address.
	misname string
	// refuseCode is the errorCode a refusing POI answers with. Zero means 1000, a
	// generic refusal. It matters because the code is the whole content of some
	// answers: 2020 says the XID is not held, which for a withdrawal is the
	// outcome, not a failure.
	refuseCode int
}

// poiEnvelope builds the response envelope a conformant NE returns: the response
// type derived from the request's, and the five fields of the schema's
// X1ResponseMessage base type — the peer's echoed back, its own stated.
//
// This fake used to answer with a bare <oK> and nothing else, which is not a
// response any conformant NE sends and which the CC-TF now refuses as
// unattributable. A stub that is not conformant tests this element against a
// fiction — and what this file is about is precisely what the CC-TF does with the
// answers it gets back.
func poiEnvelope(t *testing.T, request []byte, payload string) string {
	t.Helper()

	var in struct {
		Messages []struct {
			Type            string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
			AdmfIdentifier  string `xml:"admfIdentifier"`
			NeIdentifier    string `xml:"neIdentifier"`
			Timestamp       string `xml:"messageTimestamp"`
			Version         string `xml:"version"`
			X1TransactionID string `xml:"x1TransactionId"`
		} `xml:"x1RequestMessage"`
	}
	if err := xml.Unmarshal(request, &in); err != nil {
		t.Fatalf("fake POI could not parse the request it is answering: %v", err)
	}
	if len(in.Messages) != 1 {
		t.Fatalf("fake POI received %d request messages, want 1", len(in.Messages))
	}
	m := in.Messages[0]

	local := m.Type
	if i := strings.LastIndex(local, ":"); i >= 0 {
		local = local[i+1:]
	}

	return `<?xml version="1.0"?><x1:X1Response xmlns:x1="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
		`<x1:x1ResponseMessage xsi:type="x1:` + strings.TrimSuffix(local, "Request") + `Response">` +
		`<x1:admfIdentifier>` + m.AdmfIdentifier + `</x1:admfIdentifier>` +
		`<x1:neIdentifier>` + m.NeIdentifier + `</x1:neIdentifier>` +
		`<x1:messageTimestamp>` + m.Timestamp + `</x1:messageTimestamp>` +
		`<x1:version>` + m.Version + `</x1:version>` +
		`<x1:x1TransactionId>` + m.X1TransactionID + `</x1:x1TransactionId>` +
		payload +
		`</x1:x1ResponseMessage></x1:X1Response>`
}

func newFakePOI(t *testing.T) *fakePOI {
	t.Helper()

	p := &fakePOI{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test

		p.mu.Lock()
		p.bodies = append(p.bodies, string(body))
		p.requests++
		refuse := p.refuse
		refuseCode := p.refuseCode
		if refuseCode == 0 {
			refuseCode = 1000
		}
		if p.refuseUntilProvisioned {
			switch {
			case strings.Contains(string(body), "CreateDestinationRequest"):
				p.provisioned = true
			case !p.provisioned:
				refuse = true
			}
		}
		p.mu.Unlock()

		if strings.Contains(string(body), "GetAllDetailsRequest") {
			p.mu.Lock()
			held := append([]string(nil), p.holds...)
			fail := p.detailsFail
			p.mu.Unlock()

			if fail {
				//nolint:errcheck // test handler write
				_, _ = w.Write([]byte(poiEnvelope(t, body,
					`<x1:errorInformation><x1:errorCode>1000</x1:errorCode>`+
						`<x1:errorDescription>not ready</x1:errorDescription></x1:errorInformation>`)))

				return
			}

			p.mu.Lock()
			unhealthy := map[string]string{}
			for k, v := range p.unhealthy {
				unhealthy[k] = v
			}
			p.mu.Unlock()

			var details string
			for _, xid := range held {
				// taskStatus is a complex type in the schema; a bare string there is the
				// shape this project used to emit and no longer does.
				status := "complete"
				if s, ok := unhealthy[xid]; ok {
					status = s
				}
				details += `<x1:taskResponseDetails><x1:taskDetails><x1:xId>` + xid +
					`</x1:xId></x1:taskDetails><x1:taskStatus>` +
					`<x1:provisioningStatus>` + status + `</x1:provisioningStatus>` +
					`<x1:listOfFaults/></x1:taskStatus></x1:taskResponseDetails>`
			}

			//nolint:errcheck // test handler write
			_, _ = w.Write([]byte(poiEnvelope(t, body,
				`<x1:listOfTaskResponseDetails>`+details+`</x1:listOfTaskResponseDetails>`)))

			return
		}

		if refuse {
			//nolint:errcheck // test handler write
			_, _ = w.Write([]byte(poiEnvelope(t, body,
				`<x1:errorInformation><x1:errorCode>`+strconv.Itoa(refuseCode)+`</x1:errorCode>`+
					`<x1:errorDescription>refused</x1:errorDescription></x1:errorInformation>`)))

			return
		}

		p.mu.Lock()
		misname := p.misname
		p.mu.Unlock()

		answer := poiEnvelope(t, body, `<x1:oK>AcknowledgedAndCompleted</x1:oK>`)
		if misname != "" {
			answer = strings.Replace(answer,
				`<x1:neIdentifier>upf-1</x1:neIdentifier>`,
				`<x1:neIdentifier>`+misname+`</x1:neIdentifier>`, 1)
		}

		//nolint:errcheck // test handler write
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(p.srv.Close)

	return p
}

func (p *fakePOI) sent() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]string(nil), p.bodies...)
}

// countMessages returns how many of the recorded requests carry the given
// xsi:type.
func (p *fakePOI) countMessages(msgType string) int {
	n := 0
	for _, b := range p.sent() {
		if strings.Contains(b, `xsi:type="ns1:`+msgType+`"`) {
			n++
		}
	}

	return n
}

// triggerSubsystem builds a subsystem whose only configured capability is CC
// triggering, pointed at poi.
func triggerSubsystem(poi *fakePOI) *subsystem {
	cfg := Config{
		NEID: "smf-1",
		MDF3: "192.0.2.1:42069",
		UPFTriggers: []UPFTrigger{
			{NodeID: "10.0.1.5", X1URL: poi.srv.URL, NEID: "upf-1"},
		},
	}

	return &subsystem{
		neID:     "smf-1",
		triggers: mustRegistry(cfg),
	}
}

// TestInstallTriggersSendsWarrantIdentity is the core of the triggering interface: the trigger a
// CC-TF sends must carry the warrant XID, the session's correlation identifier and
// the UPF's own SEID as the detection criterion, and must be preceded by the
// destination it references.
func TestInstallTriggersSendsWarrantIdentity(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}

	s.installFor("session-ref-1",
		[]types.InterceptTask{warrant},
		[]upfSession{{node: upfNode("10.0.1.5"), seid: 14426627323429955319}},
		0x2632898145f4d191)

	if n := poi.countMessages("CreateDestinationRequest"); n != 1 {
		t.Errorf("CreateDestination sent %d times, want once before the first trigger", n)
	}

	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Fatalf("ActivateTask sent %d times, want once", n)
	}

	sent := poi.sent()
	// The destination must be provisioned before the trigger that names it
	// (TS 33.128 table 6.2.3-6).
	if !strings.Contains(sent[0], "CreateDestinationRequest") {
		t.Error("the first request was not CreateDestination")
	}

	activate := sent[len(sent)-1]
	for _, want := range []string{
		// The warrant, as ProductID — what makes the content attributable.
		`<ns1:productID>11111111-1111-4111-8111-111111111111</ns1:productID>`,
		// The session's correlation identifier, matching the xIRI's.
		`<ns1:correlationID>2752413510594253201</ns1:correlationID>`,
		// This UPF's SEID as the detection criterion.
		`<ext:SEID>14426627323429955319</ext:SEID>`,
		`<ns1:deliveryType>X3Only</ns1:deliveryType>`,
	} {
		if !strings.Contains(activate, want) {
			t.Errorf("trigger missing %s\ngot:\n%s", want, activate)
		}
	}

	// The trigger's own XID is the CC-TF's, allocated per (warrant, session, UPF) —
	// it must not be the warrant's, or the POI would label content with the trigger.
	if strings.Contains(activate, `<ns1:xId>11111111-1111-4111-8111-111111111111</ns1:xId>`) {
		t.Error("the trigger reused the warrant XID as its own task id")
	}
}

// TestInstallTriggersIsIdempotent covers the case where establishment and a
// mid-session activation both reach the same session: tasking a POI twice for one
// session would make it deliver every packet twice.
func TestInstallTriggersIsIdempotent(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode("10.0.1.5"), seid: 42}}

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Errorf("ActivateTask sent %d times for one session, want once", n)
	}
	// The destination is provisioned once per UPF, not once per trigger.
	if n := poi.countMessages("CreateDestinationRequest"); n != 1 {
		t.Errorf("CreateDestination sent %d times, want once per UPF", n)
	}
}

// TestInstallTriggersPerUPFAndWarrant checks the fan-out: a session on two UPFs
// needs a trigger at each, and two warrants covering it need one each — with a
// distinct trigger XID every time, but the same session correlation.
func TestInstallTriggersPerUPFAndWarrant(t *testing.T) {
	poi := newFakePOI(t)
	cfg := Config{
		NEID: "smf-1",
		MDF3: "192.0.2.1:42069",
		UPFTriggers: []UPFTrigger{
			{NodeID: "10.0.1.5", X1URL: poi.srv.URL, NEID: "upf-1"},
			{NodeID: "10.0.1.6", X1URL: poi.srv.URL, NEID: "upf-2"},
		},
	}
	s := &subsystem{neID: "smf-1", triggers: mustRegistry(cfg)}

	warrants := []types.InterceptTask{
		{XID: "11111111-1111-4111-8111-111111111111", Products: []types.ProductType{types.ProductCC}},
		{XID: "22222222-2222-4222-8222-222222222222", Products: []types.ProductType{types.ProductCC}},
	}
	upfs := []upfSession{{node: upfNode("10.0.1.5"), seid: 42}, {node: upfNode("10.0.1.6"), seid: 43}}

	s.installFor("session-ref-1", warrants, upfs, 7)

	// 2 warrants x 2 UPFs.
	if n := poi.countMessages("ActivateTaskRequest"); n != 4 {
		t.Errorf("ActivateTask sent %d times, want 4 (a warrant x UPF fan-out)", n)
	}

	if got := len(s.triggers.installed); got != 4 {
		t.Errorf("installed triggers = %d, want 4", got)
	}

	// Every trigger XID must be distinct, or one deactivation would remove another
	// agency's interception.
	seen := map[types.XID]bool{}
	for _, xid := range s.triggers.installed {
		if seen[xid] {
			t.Errorf("trigger XID %q reused across triggers", xid)
		}
		seen[xid] = true
	}
}

// TestInstallTriggersReportsRefusal covers clause 5.2.6: when a triggered POI
// refuses, the CC-TF must tell the LIPF — the warrant is authorised but no content
// will be produced, and nothing else in the system knows.
func TestInstallTriggersReportsRefusal(t *testing.T) {
	poi := newFakePOI(t)
	poi.refuse = true

	s := triggerSubsystem(poi)
	rec := &recordingTaskReporter{}
	s.taskReporter = rec

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}

	s.installFor("session-ref-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode("10.0.1.5"), seid: 42}}, 7)

	if len(rec.reports) != 1 {
		t.Fatalf("task issues reported = %d, want 1", len(rec.reports))
	}
	if rec.reports[0].xid != string(warrant.XID) {
		t.Errorf("reported XID = %q, want the warrant %q", rec.reports[0].xid, warrant.XID)
	}
	if rec.reports[0].reportType != x1.TaskReportTerminatingFault {
		t.Errorf("reportType = %q, want %q", rec.reports[0].reportType, x1.TaskReportTerminatingFault)
	}
	// The report must not name the target.
	if strings.Contains(rec.reports[0].details, "imsi") {
		t.Errorf("task issue details name a subscriber: %q", rec.reports[0].details)
	}
}

// TestInstallTriggersRetriesAfterFailure checks that a refused trigger is not
// recorded as installed: a later establishment or activation must try again, or
// one transient failure would disable the interception for the session's life.
func TestInstallTriggersRetriesAfterFailure(t *testing.T) {
	poi := newFakePOI(t)
	poi.refuse = true

	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode("10.0.1.5"), seid: 42}}

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

	if len(s.triggers.installed) != 0 {
		t.Fatalf("a refused trigger was recorded as installed: %+v", s.triggers.installed)
	}

	poi.mu.Lock()
	poi.refuse = false
	poi.mu.Unlock()

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

	if len(s.triggers.installed) != 1 {
		t.Errorf("installed = %d after a successful retry, want 1", len(s.triggers.installed))
	}
}

// TestInstallTriggersReportsMissingEndpoint covers a UPF carrying a tasked
// session's traffic that this SMF has no way to task. The interception is
// authorised and will produce nothing, so it must not pass silently.
func TestInstallTriggersReportsMissingEndpoint(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	rec := &recordingTaskReporter{}
	s.taskReporter = rec

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}

	// A UPF absent from the configured triggering endpoints.
	s.installFor("session-ref-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode("10.0.9.9"), seid: 42}}, 7)

	if poi.requests != 0 {
		t.Error("a request was sent for a UPF with no configured endpoint")
	}
	if len(rec.reports) != 1 {
		t.Fatalf("task issues reported = %d, want 1", len(rec.reports))
	}
}

// TestTakeForSessionAndWarrant pins the bookkeeping the deactivation paths depend
// on. A session's triggers are withdrawn when it is released; a warrant's are
// withdrawn when it is deactivated, wherever they were installed. Taken triggers
// move to pending rather than out of the registry: the withdrawal has been decided,
// not performed.
func TestTakeForSessionAndWarrant(t *testing.T) {
	reg := &triggerRegistry{
		installed: map[string]types.XID{},
		pending:   map[string]*pendingWithdrawal{},
	}

	// Two warrants, two sessions, two UPFs.
	for _, w := range []types.XID{"warrant-a", "warrant-b"} {
		for _, ref := range []string{"sess-1", "sess-2"} {
			for _, node := range []string{"10.0.1.5", "10.0.1.6"} {
				reg.installed[triggerKey(w, ref, node)] = types.XID(string(w) + "|" + ref + "|" + node)
			}
		}
	}
	if len(reg.installed) != 8 {
		t.Fatalf("setup: installed = %d, want 8", len(reg.installed))
	}

	// Releasing one session takes both warrants' triggers at both UPFs, and nothing
	// belonging to the other session. The UPFs come from the bookkeeping, not from
	// the session, so a session whose PFCP state is already gone is still cleaned up.
	got := reg.takeForSession("sess-1")
	for _, w := range got {
		if w.nodeID != "10.0.1.5" && w.nodeID != "10.0.1.6" {
			t.Errorf("takeForSession named an unexpected node %q", w.nodeID)
		}
	}
	if len(got) != 4 {
		t.Errorf("takeForSession returned %d triggers, want 4 (2 warrants x 2 UPFs)", len(got))
	}
	if len(reg.installed) != 4 {
		t.Errorf("installed = %d after takeForSession, want 4 (sess-2's)", len(reg.installed))
	}
	// Nothing is withdrawn yet, so the registry is still answerable for all four.
	if len(reg.pending) != 4 {
		t.Errorf("pending = %d after takeForSession, want the 4 it took — a trigger dropped "+
			"here is one the POI keeps and nothing retries", len(reg.pending))
	}

	// Deactivating a warrant takes its remaining triggers, each naming the UPF it
	// must be deactivated at.
	byWarrant := reg.takeForWarrant("warrant-a")
	for _, w := range byWarrant {
		if w.nodeID != "10.0.1.5" && w.nodeID != "10.0.1.6" {
			t.Errorf("takeForWarrant named an unexpected node %q", w.nodeID)
		}
	}
	if len(byWarrant) != 2 {
		t.Errorf("takeForWarrant returned %d triggers, want warrant-a's remaining 2", len(byWarrant))
	}
	// Only warrant-b's sess-2 pair remains.
	if len(reg.installed) != 2 {
		t.Errorf("installed = %d after takeForWarrant, want 2 (warrant-b's)", len(reg.installed))
	}
	for key := range reg.installed {
		if !strings.HasPrefix(key, "warrant-b|") {
			t.Errorf("a non-warrant-b trigger survived: %q", key)
		}
	}
}

// TestInstallTriggersReprovisionsAfterRestart: a POI restarts
// independently of this triggering function and takes the destination we
// provisioned with it. Believing otherwise meant every later trigger named a
// destination the POI no longer knew, so it duplicated the subject's traffic and
// discarded every copy while we were told interception was running.
func TestInstallTriggersReprovisionsAfterRestart(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}

	// First session: destination provisioned, trigger accepted.
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode("10.0.1.5"), seid: 42}}, 7)

	if n := poi.countMessages("CreateDestinationRequest"); n != 1 {
		t.Fatalf("CreateDestination sent %d times, want 1", n)
	}

	// The POI restarts: it has forgotten the destination, so it now refuses a
	// trigger naming it — which is the only way we can find out.
	poi.mu.Lock()
	poi.refuseUntilProvisioned = true
	poi.mu.Unlock()

	s.installFor("session-2", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode("10.0.1.5"), seid: 43}}, 9)

	// We must have re-provisioned rather than given up.
	if n := poi.countMessages("CreateDestinationRequest"); n != 2 {
		t.Errorf("CreateDestination sent %d times, want a second after the refusal", n)
	}

	// And the interception must now be installed, not abandoned.
	if len(s.triggers.installed) != 2 {
		t.Errorf("installed = %d, want both sessions tasked after the retry", len(s.triggers.installed))
	}
}

// TestReconcileWithdrawsTaskingFromAPreviousLife: after a restart
// this process has no record of the triggers it installed, while the POI still
// holds them — and tasking nobody can withdraw does not stop, not even when the
// warrant is revoked. The keepalive fail-safe cannot cover it, because a restarted
// triggering function is alive.
func TestReconcileWithdrawsTaskingFromAPreviousLife(t *testing.T) {
	poi := newFakePOI(t)
	poi.mu.Lock()
	poi.holds = []string{"aaaaaaaa-1111-4111-8111-111111111111", "bbbbbbbb-2222-4222-8222-222222222222"}
	poi.mu.Unlock()

	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}

	s.reconcileOne()

	// Both must be withdrawn: this process installed neither.
	if n := poi.countMessages("DeactivateTaskRequest"); n != 2 {
		t.Errorf("sent %d deactivations, want 2 — stale tasking would keep running", n)
	}
}

// TestReconcileLeavesThisProcesssOwnTasking guards the race the ownership check
// exists for: reconciliation runs alongside ordinary triggering, so a session
// establishing at that moment must not have its brand-new trigger cleaned up.
func TestReconcileLeavesThisProcesssOwnTasking(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode("10.0.1.5"), seid: 42}}, 7)

	// The POI reports exactly what this process just installed.
	var mine []string
	for _, xid := range s.triggers.installed {
		mine = append(mine, string(xid))
	}

	poi.mu.Lock()
	poi.holds = mine
	poi.mu.Unlock()

	s.reconcileOne()

	if n := poi.countMessages("DeactivateTaskRequest"); n != 0 {
		t.Errorf("sent %d deactivations for tasking this process installed itself", n)
	}
}

// recordingTaskReporter captures ReportTaskIssue calls.
type recordingTaskReporter struct {
	reports []taskReport
}

type taskReport struct {
	xid, reportType, details string
}

func (r *recordingTaskReporter) NotifyTask(xid, reportType, details string) {
	r.reports = append(r.reports, taskReport{xid, reportType, details})
}

// reconcileOne runs the reconciliation that reconcileTriggers gives each endpoint
// its own goroutine for, synchronously, so a test can assert on what it did. The
// fan-out exists so that one unreachable POI does not hold up the others; nothing
// about one endpoint's reconciliation depends on it.
func (s *subsystem) reconcileOne() {
	s.reconcileEndpoint("10.0.1.5", s.triggers.endpoints["10.0.1.5"])
}

// installFor mirrors what triggerCC does — claim the triggers under the caller's
// lock, then install them — so a test can drive both halves synchronously. The
// two are separate in production only because the X1 exchange must not run on the
// signalling path.
func (s *subsystem) installFor(ref string, tasks []types.InterceptTask, upfs []upfSession, correlation uint64) {
	planned, unreachable := s.triggers.plan(ref, tasks, upfs, correlation)
	for _, warrant := range unreachable {
		s.reportTaskIssue(warrant, "no triggering endpoint configured for a UPF serving the target")
	}
	s.installTriggers(planned)
}

// TestTriggerInstalledAfterReleaseIsWithdrawn: the X1 exchange runs off the
// signalling path, so a short-lived session can be released while its trigger is
// still being installed. The withdrawal then runs against a registry entry whose
// trigger does not exist at the POI yet, and used to withdraw nothing — leaving a
// trigger in place that reconciliation (startup only) and the POI's own fail-safe
// (this SMF is alive and sending keepalives) would both never reach.
//
// The pending-removal state is what closes it now, and it closes it in either
// order: the withdrawal that arrives before the trigger exists stays pending and
// retries, so the install need only leave it alone. Exactly one party withdraws,
// which is the point — two would each read an answer meant for the other.
func TestTriggerInstalledAfterReleaseIsWithdrawn(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode("10.0.1.5"), seid: 0x2632898145f4d191}}

	// Claim, as triggerCC does under the session lock.
	planned, unreachable := s.triggers.plan("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	if len(unreachable) != 0 || len(planned) != 1 {
		t.Fatalf("plan() = %d triggers, %d unreachable; want 1, 0", len(planned), len(unreachable))
	}

	// The session is released before the install goroutine gets to run its X1
	// exchange — the ordering the session lock permits and this guards against.
	pending := s.triggers.takeForSession("session-ref-1")
	if len(pending) != 1 {
		t.Fatalf("takeForSession returned %d triggers, want 1", len(pending))
	}

	s.installTriggers(planned)
	s.deactivate(pending)

	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Fatalf("ActivateTaskRequest count = %d, want 1", n)
	}
	if n := poi.countMessages("DeactivateTaskRequest"); n != 1 {
		t.Errorf("DeactivateTaskRequest count = %d, want 1 — a trigger installed after "+
			"its session was released must be withdrawn, and withdrawn once", n)
	}
	if !strings.Contains(strings.Join(poi.sent(), ""), string(planned[0].trigger.XID)) {
		t.Error("the withdrawal did not name the trigger that was installed")
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after an acknowledged withdrawal, want 0", n)
	}
}

// TestTriggerNotInstalledBeforeCorrelationExists: the correlation identifier is
// the anchor's F-SEID, and until the anchor's PFCP session exists there is none.
// A trigger without it is refused by x1.Trigger, so sending one would report a
// fault to the LIPF that is not one — the anchor's establishment response brings
// the CC-TF back here.
func TestTriggerNotInstalledBeforeCorrelationExists(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	rec := &recordingTaskReporter{}
	s.taskReporter = rec

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode("10.0.1.5"), seid: 0x2632898145f4d191}}

	s.installFor("session-ref-1", []types.InterceptTask{warrant}, upfs, 0)

	if n := poi.countMessages("ActivateTaskRequest"); n != 0 {
		t.Errorf("sent %d triggers with no correlation identifier, want 0", n)
	}
	if len(rec.reports) != 0 {
		t.Errorf("reported %v to the LIPF; a session whose anchor is not up yet is not a fault", rec.reports)
	}
}

// ── Matching a session's UPF to its triggering endpoint ──
//
// These four cover the CC-TF's join between two independently configured things:
// the UPF named in li.upfTriggers, and the UPF actually serving a session. Getting
// it wrong is invisible from outside the SMF — the warrant stays active, the
// datapath keeps duplicating, and the content is dropped as unattributable — so
// each of these asserts a property that produced silence rather than an error.

// TestMatchEndpointFollowsAUPFThatChangesAddress is the regression test. The
// registry used to store the address its configured NodeID resolved to at
// construction, which froze a value that moves: recreating the UPF's Service gave
// it a new address, the session path followed within the minute (the SMF refreshes
// its DNS cache on a ticker) and the registry did not, so every CC warrant for that
// UPF reported "no triggering endpoint" until the SMF was restarted.
func TestMatchEndpointFollowsAUPFThatChangesAddress(t *testing.T) {
	const name = "upf-moving.test"
	smfctx.InsertDnsHostIp(name, net.ParseIP("10.0.1.5"))

	reg := mustRegistry(Config{
		NEID: "smf-1", MDF3: "192.0.2.1:42069",
		UPFTriggers: []UPFTrigger{{NodeID: name, X1URL: "https://upf-1:8443/X1/NE", NEID: "upf-1"}},
	})

	if _, _, ok := reg.matchEndpoint(upfNode("10.0.1.5")); !ok {
		t.Fatal("a session on the UPF's current address found no triggering endpoint")
	}

	// The Service is recreated with a different address; the SMF's cache catches up.
	smfctx.InsertDnsHostIp(name, net.ParseIP("10.0.9.9"))

	if _, _, ok := reg.matchEndpoint(upfNode("10.0.9.9")); !ok {
		t.Error("the UPF changed address and its triggering endpoint became unreachable " +
			"for the life of the process; content interception is silently dead until an SMF restart")
	}
	if _, _, ok := reg.matchEndpoint(upfNode("10.0.1.5")); ok {
		t.Error("a session on the UPF's old address still matched; the endpoint is being " +
			"selected from a stale address rather than the current one")
	}
}

// TestMatchEndpointNeverMatchesUnresolvableNodes is the one with a security
// consequence. Failed resolution yields 0.0.0.0, so matching on a resolved address
// made every unresolvable name equal to every other — the defect upstream fixed for
// gNB names in nodeInLinks (#613). Here it would hand one UPF's CC-POI a different
// UPF's warrant, delivering content under a warrant that does not cover it.
func TestMatchEndpointNeverMatchesUnresolvableNodes(t *testing.T) {
	reg := mustRegistry(Config{
		NEID: "smf-1", MDF3: "192.0.2.1:42069",
		UPFTriggers: []UPFTrigger{{NodeID: "upf-a.invalid", X1URL: "https://upf-a:8443/X1/NE", NEID: "upf-a"}},
	})

	if _, _, ok := reg.matchEndpoint(upfNode("upf-b.invalid")); ok {
		t.Error("a session on upf-b matched upf-a's triggering endpoint because neither name " +
			"resolves; one UPF's content would be tasked under another's warrant")
	}
}

// TestMatchEndpointPrefersIdentityOverResolution pins the ordering. Identity is
// exact and needs no DNS, so it must be tried first: a node named the way the slice
// topology names it must match its own endpoint even when another endpoint's
// address happens to be what that name resolves to.
func TestMatchEndpointPrefersIdentityOverResolution(t *testing.T) {
	const name = "upf-named.test"
	smfctx.InsertDnsHostIp(name, net.ParseIP("10.0.2.7"))

	reg := mustRegistry(Config{
		NEID: "smf-1", MDF3: "192.0.2.1:42069",
		UPFTriggers: []UPFTrigger{
			{NodeID: name, X1URL: "https://upf-named:8443/X1/NE", NEID: "upf-named"},
			{NodeID: "10.0.2.7", X1URL: "https://upf-numeric:8443/X1/NE", NEID: "upf-numeric"},
		},
	})

	key, _, ok := reg.matchEndpoint(upfNode(name))
	if !ok {
		t.Fatal("a session identifying its UPF by name found no endpoint")
	}
	if key != name {
		t.Errorf("matched %q, want %q: an address match won over an exact identity match", key, name)
	}
}

// TestTriggerRegistryRejectsAmbiguousNode covers the silent half of it. Two
// entries naming one node used to collapse into a single registry entry, the second
// overwriting the first, so a two-UPF configuration presented as a one-UPF registry
// and the displaced UPF's content was never attributable — with nothing logged and
// no fault raised.
func TestTriggerRegistryRejectsAmbiguousNode(t *testing.T) {
	_, err := newTriggerRegistry(Config{
		NEID: "smf-1", MDF3: "192.0.2.1:42069",
		UPFTriggers: []UPFTrigger{
			{NodeID: "10.0.1.5", X1URL: "https://upf-1:8443/X1/NE", NEID: "upf-1"},
			{NodeID: "10.0.1.5", X1URL: "https://upf-2:8443/X1/NE", NEID: "upf-2"},
		},
	}, nil, nil)
	if err == nil {
		t.Error("an ambiguous upfTriggers configuration was accepted; one UPF's endpoint " +
			"silently replaces another's and its content cannot be attributed")
	}
}

// TestMatchEndpointIsDeterministic guards the ambiguous case. Two configured nodes
// can resolve to one address — transiently while a Service is recreated, or
// permanently by mistake — and picking between them by Go's map order would send a
// session's triggers to a different UPF from one establishment to the next, each
// carrying the X3 destination with it. The final review found this same
// nondeterminism in warrant selection at the CC-POI.
func TestMatchEndpointIsDeterministic(t *testing.T) {
	smfctx.InsertDnsHostIp("upf-one.test", net.ParseIP("10.0.3.3"))
	smfctx.InsertDnsHostIp("upf-two.test", net.ParseIP("10.0.3.3"))

	reg := mustRegistry(Config{
		NEID: "smf-1", MDF3: "192.0.2.1:42069",
		UPFTriggers: []UPFTrigger{
			{NodeID: "upf-one.test", X1URL: "https://upf-one:8443/X1/NE", NEID: "upf-one"},
			{NodeID: "upf-two.test", X1URL: "https://upf-two:8443/X1/NE", NEID: "upf-two"},
		},
	})

	first, _, ok := reg.matchEndpoint(upfNode("10.0.3.3"))
	if !ok {
		t.Fatal("no endpoint matched an address both configured nodes resolve to")
	}
	for range 50 {
		got, _, _ := reg.matchEndpoint(upfNode("10.0.3.3"))
		if got != first {
			t.Fatalf("matched %q then %q: the same session would be triggered at a "+
				"different UPF on re-establishment", first, got)
		}
	}
}

// TestReconcileReportsATriggerThePOISaysIsNotRunning covers the one thing a CC
// triggering function exists to notice: a trigger it installed, for a live
// warrant, that the POI is not actually running.
//
// Nothing else can report it. The POI answers to this SMF over the internal
// triggering interface, not to the ADMF, so the ADMF cannot ask it directly — and
// this SMF used to read the POI's reply for XIDs and discard everything else,
// including the task's provisioning status and its unresolved faults. The
// interception was stopped and every party believed it was running.
func TestReconcileReportsATriggerThePOISaysIsNotRunning(t *testing.T) {
	var mu sync.Mutex
	var reports []string
	admf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test
		mu.Lock()
		reports = append(reports, string(body))
		mu.Unlock()
		//nolint:errcheck // test handler write
		_, _ = w.Write([]byte(`<?xml version="1.0"?><X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">` +
			`<x1ResponseMessage><oK>AcknowledgedAndCompleted</oK></x1ResponseMessage></X1Response>`))
	}))
	defer admf.Close()

	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}
	s.reporter = x1.NewReporter(admf.URL, "admf", "smf", nil)

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode("10.0.1.5"), seid: 42}}, 7)

	var mine []string
	for _, xid := range s.triggers.installed {
		mine = append(mine, string(xid))
	}
	if len(mine) == 0 {
		t.Fatal("no trigger was installed, so this test would prove nothing")
	}

	// The POI holds exactly what this process installed, and reports the first as
	// not provisioned.
	poi.mu.Lock()
	poi.holds = mine
	poi.unhealthy = map[string]string{mine[0]: "failed"}
	poi.mu.Unlock()

	s.reconcileOne()

	// It is ours, so it must not be withdrawn — the fault is reported, not acted on
	// by tearing down a live warrant's interception.
	if n := poi.countMessages("DeactivateTaskRequest"); n != 0 {
		t.Errorf("sent %d deactivations for a faulty trigger; the warrant is live", n)
	}

	mu.Lock()
	defer mu.Unlock()
	var found bool
	for _, body := range reports {
		if strings.Contains(body, "triggerFaulty") {
			found = true
			if !strings.Contains(body, "failed") {
				t.Errorf("report does not say what the POI reported:\n%s", body)
			}
			// The ADMF is told how much is wrong, never whose: an NE-level issue
			// carries no target identity.
			if strings.Contains(body, mine[0]) {
				t.Errorf("NE-level report names a task XID:\n%s", body)
			}
		}
	}
	if !found {
		t.Errorf("no triggerFaulty report reached the ADMF; got %d report(s): %v", len(reports), reports)
	}
}

// installOneTrigger installs a single CC trigger for a live session and returns
// the warrant and the trigger XID the CC-TF allocated for it. The withdrawal tests
// all start from here: a warrant, a session that stays up, and a POI that holds a
// trigger.
func installOneTrigger(t *testing.T, s *subsystem) (warrant types.InterceptTask, trigger types.XID) {
	t.Helper()

	warrant = types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode("10.0.1.5"), seid: 42}}, 7)

	for _, xid := range s.triggers.installed {
		trigger = xid
	}
	if trigger == "" {
		t.Fatal("no trigger was installed, so this test would prove nothing")
	}

	return warrant, trigger
}

// TestWithdrawnWarrantIsStillTrackedWhenThePOIRefuses is the regression test for
// the defect this change exists for, and it is worth exactly what watching it fail
// is worth: on the previous code it fails on the first assertion.
//
// A warrant is withdrawn while its session is live. The X1 DeactivateTask to the
// serving UPF fails. The bookkeeping had already been deleted on the way to that
// attempt, so nothing retried and nothing remembered: the UPF kept the trigger,
// kept the DUPL FAR, and kept delivering the subject's content to MDF3 under a
// warrant that no longer authorised it. No participant was in a position to notice
// — the SMF believed it had withdrawn the trigger, the UPF was never told, and the
// mediation function received well-formed, correctly attributed product.
func TestWithdrawnWarrantIsStillTrackedWhenThePOIRefuses(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant, trigger := installOneTrigger(t, s)

	// The POI stops answering. Its session is untouched: this is the withdrawal of
	// authority from an interception that is otherwise running perfectly.
	poi.mu.Lock()
	poi.refuse = true
	poi.mu.Unlock()

	// The X1 deactivation path, as reportDeactivation reaches it.
	pending := s.triggers.takeForWarrant(warrant.XID)
	if len(pending) != 1 {
		t.Fatalf("takeForWarrant returned %d triggers, want 1", len(pending))
	}

	held, withdrawing := s.triggers.holds(trigger)
	if !held {
		t.Fatal("the registry forgot a trigger it has not been told is gone — the UPF is " +
			"still duplicating under a withdrawn warrant and nothing will ever reclaim it")
	}
	if !withdrawing {
		t.Error("the trigger is held but not marked as being withdrawn, so reconciliation " +
			"would treat it as live tasking")
	}

	// Retry until the POI answers, on a clock the test owns. The registry stays
	// answerable for the trigger throughout — that is what makes the retry possible
	// at all.
	attempts := 0
	s.triggers.sleep = func(time.Duration) {
		attempts++
		if held, _ := s.triggers.holds(trigger); !held {
			t.Error("the registry dropped the trigger between attempts")
		}
		if attempts == 2 {
			poi.mu.Lock()
			poi.refuse = false
			poi.mu.Unlock()
		}
	}
	s.deactivate(pending)

	if held, _ := s.triggers.holds(trigger); held {
		t.Error("the registry still holds a trigger the POI acknowledged withdrawing")
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after acknowledgement, want 0", n)
	}
}

// TestWithdrawalRetriesOnBackoff pins the shape of the retry: bounded in effort so
// it cannot spin against a POI that is down, unbounded in intent so it cannot give
// up while it still believes a trigger is installed. A retry that expires is this
// change's defect arriving later.
func TestWithdrawalRetriesOnBackoff(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant, _ := installOneTrigger(t, s)

	poi.mu.Lock()
	poi.refuse = true
	poi.mu.Unlock()

	pending := s.triggers.takeForWarrant(warrant.XID)

	// The clock is the test's, so a backoff measured in minutes costs nothing. The
	// POI starts answering after the fifth failure, which is where the schedule has
	// levelled off at the keepalive interval.
	var waits []time.Duration
	s.triggers.sleep = func(d time.Duration) {
		waits = append(waits, d)
		if n := s.triggers.pendingCount(); n != 1 {
			t.Errorf("pending = %d during retry %d, want exactly the one being withdrawn", n, len(waits))
		}
		if len(waits) == 5 {
			poi.mu.Lock()
			poi.refuse = false
			poi.mu.Unlock()
		}
	}

	before := poi.countMessages("DeactivateTaskRequest")
	s.deactivate(pending)

	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second}
	if !slices.Equal(waits, want) {
		t.Errorf("backoff was %v, want %v — doubling from 5s and level at the keepalive interval", waits, want)
	}
	if n := poi.countMessages("DeactivateTaskRequest") - before; n != 6 {
		t.Errorf("sent %d withdrawals, want 6 (five refused, one acknowledged)", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d once the POI acknowledged, want 0", n)
	}
}

// TestWithdrawalFailureAndStuckAreDistinctReports: the LIPF is the only party that
// can act on a withdrawal this element cannot deliver, and it can only act if the
// two conditions reach it as two conditions. "The last attempt failed" and
// "authority was removed five minutes ago and content is probably still flowing"
// call for different responses, and an operator who sees the first repeated
// indefinitely learns nothing from the hundredth.
func TestWithdrawalFailureAndStuckAreDistinctReports(t *testing.T) {
	var mu sync.Mutex
	var reports []string
	admf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test
		mu.Lock()
		reports = append(reports, string(body))
		mu.Unlock()
		//nolint:errcheck // test handler write
		_, _ = w.Write([]byte(`<?xml version="1.0"?><X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">` +
			`<x1ResponseMessage><oK>AcknowledgedAndCompleted</oK></x1ResponseMessage></X1Response>`))
	}))
	defer admf.Close()

	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}
	s.reporter = x1.NewReporter(admf.URL, "admf", "smf", nil)

	warrant, trigger := installOneTrigger(t, s)

	poi.mu.Lock()
	poi.refuse = true
	poi.mu.Unlock()

	// A clock that advances by more than the stuck window between the second and
	// third attempt, so the test observes the transition rather than waiting for it.
	now := time.Now()
	s.triggers.now = func() time.Time { return now }
	pending := s.triggers.takeForWarrant(warrant.XID)

	rounds := 0
	s.triggers.sleep = func(time.Duration) {
		rounds++
		if rounds == 2 {
			now = now.Add(withdrawalStuckAfter + time.Second)
		}
		if rounds == 5 {
			poi.mu.Lock()
			poi.refuse = false
			poi.mu.Unlock()
		}
	}
	s.deactivate(pending)

	mu.Lock()
	defer mu.Unlock()
	failed, stuck := 0, 0
	for _, body := range reports {
		if strings.Contains(body, x1.NEIssueTaskingWithdrawalFailed) {
			failed++
		}
		if strings.Contains(body, x1.NEIssueTaskingWithdrawalStuck) {
			stuck++
		}
		// The fault channel is inside the LI domain, but which subject a warrant
		// covers is not its business, and neither is which warrant.
		if strings.Contains(body, string(trigger)) || strings.Contains(body, string(warrant.XID)) {
			t.Errorf("an NE-level withdrawal report names an identifier:\n%s", body)
		}
	}
	if failed != 1 {
		t.Errorf("taskingWithdrawalFailed reported %d times over six attempts, want 1", failed)
	}
	if stuck != 1 {
		t.Errorf("taskingWithdrawalStuck reported %d times, want 1 — it is a condition, not a tick", stuck)
	}
}

// TestReconcileLeavesAWithdrawalInFlightAlone: reconciliation and the withdrawal
// retry loop both act on tasking the POI still holds, and a trigger being
// withdrawn is visible to both. Two parties sending DeactivateTask for one XID
// each read an answer meant for the other — one sees an acknowledgement for a task
// the other has already removed and concludes the withdrawal landed. The registry
// answers "mine, and on its way out", which is what keeps reconciliation off it.
func TestReconcileLeavesAWithdrawalInFlightAlone(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant, trigger := installOneTrigger(t, s)

	// The warrant is withdrawn and the POI has not acknowledged, so the trigger is
	// pending — and the POI, asked what it holds, still reports it.
	s.triggers.takeForWarrant(warrant.XID)
	poi.mu.Lock()
	poi.holds = []string{string(trigger)}
	poi.mu.Unlock()

	before := poi.countMessages("DeactivateTaskRequest")
	s.reconcileOne()

	if n := poi.countMessages("DeactivateTaskRequest") - before; n != 0 {
		t.Errorf("reconciliation sent %d withdrawals for a trigger already being withdrawn, want 0", n)
	}
}

// TestKeepalivesFollowTaskingRatherThanConfiguration: the POI's fail-safe purge is
// the last mechanism able to reclaim tasking a triggering function can no longer
// name, and keeping every configured endpoint alive on a timer disables it by
// construction. A POI holding a forgotten trigger was being told, once a minute,
// that the function responsible for it was alive and well.
func TestKeepalivesFollowTaskingRatherThanConfiguration(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}
	endpoint := s.triggers.endpoints["10.0.1.5"]

	// Reconciled and holding nothing: there is nothing to keep, so the POI is left
	// to lapse whatever it still holds.
	endpoint.markReconciled()
	if s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Error("an SMF holding no content tasking keeps a POI alive, which is what makes " +
			"its fail-safe unreachable")
	}

	warrant, _ := installOneTrigger(t, s)
	if !s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Error("a POI holding this SMF's live trigger is not kept alive; its fail-safe " +
			"would purge an authorised interception")
	}

	// A withdrawal in flight still counts. Going silent under it would ask the POI's
	// fail-safe to finish a job this process has not given up on, and the fail-safe
	// takes everything at that POI with it.
	pending := s.triggers.takeForWarrant(warrant.XID)
	if !s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Error("a POI is left to lapse while a withdrawal to it is still pending")
	}

	s.deactivate(pending)
	if s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Error("keepalives continue after the last trigger was withdrawn and acknowledged")
	}
}

// TestKeepalivesWaitForReconciliation is the inversion D3 exists for. A restarted
// SMF is *present*, so the POI's fail-safe will not act while it is being kept
// alive — and until reconciliation completes, this process cannot name what that
// POI holds and therefore could never withdraw it, not even when the warrant
// behind it is revoked. Staying silent means such tasking lapses instead of
// persisting: the failure mode inverts from "interception survives" to
// "interception stops", which is the direction a fail-safe must fail in.
func TestKeepalivesWaitForReconciliation(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}
	endpoint := s.triggers.endpoints["10.0.1.5"]

	// A session establishes before reconciliation has finished, so this process does
	// hold tasking at the POI — and still owes it nothing, because what it cannot
	// name is what the fail-safe is for.
	installOneTrigger(t, s)
	if s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Error("a POI is kept alive before this process has established what it holds")
	}

	s.reconcileOne()
	if !s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Error("a reconciled POI holding live tasking is not kept alive")
	}
}

// TestReconcileRetriesUntilThePOIAnswers: an endpoint unreachable at startup and
// reachable a minute later is the ordinary shape of a whole-cluster restart. One
// attempt is not reconciliation — abandoning the POI left tasking this process
// could not name, for the life of the process.
func TestReconcileRetriesUntilThePOIAnswers(t *testing.T) {
	poi := newFakePOI(t)
	poi.mu.Lock()
	poi.detailsFail = true
	poi.holds = []string{"aaaaaaaa-1111-4111-8111-111111111111"}
	poi.mu.Unlock()

	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}
	endpoint := s.triggers.endpoints["10.0.1.5"]

	attempts := 0
	s.triggers.sleep = func(time.Duration) {
		attempts++
		if endpoint.isReconciled() {
			t.Error("the endpoint counts as reconciled while it is still refusing to say what it holds")
		}
		if attempts == 2 {
			poi.mu.Lock()
			poi.detailsFail = false
			poi.mu.Unlock()
		}
	}
	s.reconcileOne()

	if attempts != 2 {
		t.Errorf("reconciliation waited %d times, want 2 — two failures then an answer", attempts)
	}
	if !endpoint.isReconciled() {
		t.Error("the endpoint is not reconciled after the POI answered")
	}
	// And what it found is withdrawn durably, not fired and forgotten: the pending
	// state is empty because the POI acknowledged, not because nobody was watching.
	if n := poi.countMessages("DeactivateTaskRequest"); n != 1 {
		t.Errorf("sent %d withdrawals for the one orphan the POI reported, want 1", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after an acknowledged withdrawal, want 0", n)
	}
}

// TestReconcileWithdrawalIsRetriedLikeAnyOther: reconciliation's own withdrawals
// used to be the one unchecked path left — the tasking least able to survive being
// forgotten, since by definition nothing else knows it exists.
func TestReconcileWithdrawalIsRetriedLikeAnyOther(t *testing.T) {
	poi := newFakePOI(t)
	poi.mu.Lock()
	poi.holds = []string{"aaaaaaaa-1111-4111-8111-111111111111"}
	poi.refuse = true // GetAllDetails still answers; DeactivateTask does not
	poi.mu.Unlock()

	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}

	attempts := 0
	s.triggers.sleep = func(time.Duration) {
		attempts++
		if n := s.triggers.pendingCount(); n != 1 {
			t.Errorf("pending = %d while an orphan's withdrawal is unacknowledged, want 1", n)
		}
		if attempts == 2 {
			poi.mu.Lock()
			poi.refuse = false
			poi.mu.Unlock()
		}
	}
	s.reconcileOne()

	if n := poi.countMessages("DeactivateTaskRequest"); n != 3 {
		t.Errorf("sent %d withdrawals, want 3 (two refused, one acknowledged)", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d once the orphan was acknowledged, want 0", n)
	}
}

// TestFailSafeCannotReclaimAnOrphanBesideLiveTasking is the documented limit of the
// backstop, not a behaviour to rely on. The POI's fail-safe is per-connection: it
// purges all of an endpoint's tasking or none of it. So an orphan at an endpoint
// that also holds a live task is preserved by the keepalives that live task earns,
// and no amount of gating changes that. Durable withdrawal (the pending state) is
// the remedy; this only makes the backstop reachable in the case where the
// endpoint's last task was the one that failed to withdraw.
func TestFailSafeCannotReclaimAnOrphanBesideLiveTasking(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}
	endpoint := s.triggers.endpoints["10.0.1.5"]
	endpoint.markReconciled()

	// One live warrant's trigger, installed and running.
	warrant, live := installOneTrigger(t, s)

	// And an orphan the POI holds that this process is not tracking — the state a
	// forgotten withdrawal leaves behind, and the reason the pending state exists.
	orphan := "99999999-9999-4999-8999-999999999999"
	poi.mu.Lock()
	poi.holds = []string{string(live), orphan}
	poi.mu.Unlock()

	if held, _ := s.triggers.holds(types.XID(orphan)); held {
		t.Fatal("the orphan is tracked, so this test would not describe an orphan")
	}
	// The live trigger keeps the endpoint alive, so the POI's fail-safe never fires
	// and the orphan keeps duplicating alongside it.
	if !s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Fatal("the endpoint is not kept alive despite holding a live trigger")
	}

	// Only once the live trigger is withdrawn and acknowledged does the endpoint
	// fall silent — and only then can the fail-safe reclaim the orphan.
	s.deactivate(s.triggers.takeForWarrant(warrant.XID))
	if s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Error("the endpoint is still kept alive with nothing of ours left at it, so the " +
			"orphan survives even the case this backstop does cover")
	}
}

// TestRetargetDoesNotReapTheTriggerItInstalled is the race the one-event contract
// removes. A ModifyTask keeps the XID, and this registry is keyed by the warrant
// XID, so "the old task's teardown" and "the new task's installation" address the
// same entries. Under the two-event contract the activation ran first and
// installed, asynchronously, while the deactivation that followed took everything
// the warrant held — including what had just been installed — and the interception
// the ADMF had just ordered was gone with nothing left to say so.
//
// Now the modification computes the sessions the task still covers and reads the
// registry once, so a trigger for a session that survives the retarget is never
// among what is withdrawn, whatever order the goroutines run in.
func TestRetargetDoesNotReapTheTriggerItInstalled(t *testing.T) {
	const warrant = types.XID("11111111-1111-4111-8111-111111111111")

	for range 200 {
		poi := newFakePOI(t)
		s := triggerSubsystem(poi)
		s.taskReporter = &recordingTaskReporter{}
		task := types.InterceptTask{XID: warrant, Products: []types.ProductType{types.ProductCC}}

		// The old target's session, tasked before the modification.
		s.installFor("session-old", []types.InterceptTask{task},
			[]upfSession{{node: upfNode("10.0.1.5"), seid: 42}}, 7)

		var wg sync.WaitGroup
		wg.Add(2)
		// The new target's session being tasked, off the signalling path.
		go func() {
			defer wg.Done()
			s.installFor("session-new", []types.InterceptTask{task},
				[]upfSession{{node: upfNode("10.0.1.5"), seid: 43}}, 9)
		}()
		// The modification's own teardown, keeping the sessions the task still covers.
		go func() {
			defer wg.Done()
			s.deactivate(s.triggers.takeForWarrantExcept(warrant, map[string]bool{"session-new": true}))
		}()
		wg.Wait()

		key := triggerKey(warrant, "session-new", "10.0.1.5")
		if _, held := s.triggers.installed[key]; !held {
			t.Fatalf("the retarget reaped the trigger it had just installed for the new target; "+
				"installed = %v", s.triggers.installed)
		}
		if _, gone := s.triggers.installed[triggerKey(warrant, "session-old", "10.0.1.5")]; gone {
			t.Fatal("the trigger for a session the task no longer covers survived the retarget")
		}
		if n := s.triggers.pendingCount(); n != 0 {
			t.Fatalf("pending = %d after an acknowledged withdrawal, want 0", n)
		}
	}
}

// TestAReactivatedWarrantDoesNotDisplaceTheWithdrawalInFlight: the two maps are
// not in step. A warrant deactivated and re-activated while its POI is unreachable
// claims the same (warrant, session, UPF) key again under a new XID, while the old
// XID is still being withdrawn. Both are this registry's responsibility and it must
// be able to hold both — the first's acknowledgement must not clear the second's
// record, which would leave a trigger installed with nothing tracking it.
func TestAReactivatedWarrantDoesNotDisplaceTheWithdrawalInFlight(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant, first := installOneTrigger(t, s)

	// The POI stops answering, and the warrant is withdrawn.
	poi.mu.Lock()
	poi.refuse = true
	poi.mu.Unlock()
	pending := s.triggers.takeForWarrant(warrant.XID)

	// The ADMF re-activates the same warrant on the same session before the
	// withdrawal has landed. The trigger key is the same; the XID is not.
	poi.mu.Lock()
	poi.refuse = false
	poi.mu.Unlock()
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode("10.0.1.5"), seid: 42}}, 7)

	var second types.XID
	for _, xid := range s.triggers.installed {
		second = xid
	}
	if second == "" || second == first {
		t.Fatalf("the re-activation claimed no new trigger (first %q, second %q)", first, second)
	}
	if n := s.triggers.pendingCount(); n != 1 {
		t.Fatalf("pending = %d after a re-activation over a pending withdrawal, want the 1 being withdrawn", n)
	}

	// And the re-activated warrant is withdrawn in its turn, before the first
	// withdrawal has been acknowledged. Both triggers are now this registry's
	// responsibility, under one trigger key.
	poi.mu.Lock()
	poi.refuse = true
	poi.mu.Unlock()
	again := s.triggers.takeForWarrant(warrant.XID)
	if n := s.triggers.pendingCount(); n != 2 {
		t.Fatalf("pending = %d with two withdrawals outstanding for one trigger key, want 2 — "+
			"the second displaced the first and one of them is now tracked by nobody", n)
	}

	// The first withdrawal lands. It must clear its own record and leave the
	// second's alone: the second trigger is still installed at the POI.
	poi.mu.Lock()
	poi.refuse = false
	poi.mu.Unlock()
	s.deactivate(pending)

	if held, withdrawing := s.triggers.holds(second); !held || !withdrawing {
		t.Error("the acknowledgement of the first trigger's withdrawal took the second's " +
			"record with it, leaving a trigger installed at the POI with nothing tracking it")
	}
	if n := s.triggers.pendingCount(); n != 1 {
		t.Errorf("pending = %d after one of two withdrawals was acknowledged, want the other one", n)
	}

	s.deactivate(again)
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after both withdrawals were acknowledged, want 0", n)
	}
}

// TestAnUnattributableAnswerKeepsTheWithdrawalPending is task 3.8 of
// `fix-li-x1-response-binding`, asserted rather than assumed.
//
// Validating responses turns silent successes on the withdrawal path into visible
// failures, and this change was sequenced behind `fix-li-withdrawal-durability`
// precisely because a visible failure used to be discarded as silently as the
// success was. So: a POI that acknowledges under the wrong NE identifier is
// refused, and the withdrawal it refused must stay pending and keep being retried
// rather than being forgotten.
// TestAKeepaliveAnsweredByTheWrongElementIsReported is the gap verification found
// after the rest of this change was written: every tasking path reported an
// unattributable answer and the keepalive discarded one.
//
// The discard was deliberate and right about transport — a missed keepalive is
// transient and the POI's own fail-safe covers a POI that has gone. It was wrong
// about binding. The keepalive is the exchange whose entire purpose is to say the
// peer is still there, so an answer from an element this SMF did not address means
// it believes a POI is alive on the strength of a stranger's answer. That is the
// silent condition this change exists to remove, on the one exchange where nothing
// downstream would ever contradict it.
func TestAKeepaliveAnsweredByTheWrongElementIsReported(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)

	var reported []error
	s.triggers.reportUnattributable = func(err error) { reported = append(reported, err) }

	// A keepalive is owed only for a POI this function believes holds its tasking.
	installOneTrigger(t, s)
	for _, e := range s.triggers.endpoints {
		e.markReconciled()
	}

	// Answering correctly, under a name this SMF did not address.
	poi.mu.Lock()
	poi.misname = wrongNE
	poi.mu.Unlock()

	s.triggers.keepaliveRound()

	if len(reported) != 1 {
		t.Fatalf("a keepalive answered by %s produced %d reports, want 1 — this SMF holds a POI alive on an answer from something else", wrongNE, len(reported))
	}
	var unattributable *x1.ResponseError
	if !errors.As(reported[0], &unattributable) {
		t.Fatalf("reported %v, want an *x1.ResponseError naming the field that disagreed", reported[0])
	}
	if unattributable.Field != "neIdentifier" {
		t.Errorf("the report names %q; the misnaming peer is detected by neIdentifier", unattributable.Field)
	}

	// And a POI answering under its own name reports nothing, or the condition would
	// be noise on every healthy tick.
	poi.mu.Lock()
	poi.misname = ""
	poi.mu.Unlock()

	reported = nil
	s.triggers.keepaliveRound()

	if len(reported) != 0 {
		t.Errorf("a healthy keepalive produced %d reports, want 0", len(reported))
	}
}

func TestAnUnattributableAnswerKeepsTheWithdrawalPending(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}

	warrant, _ := installOneTrigger(t, s)

	// The POI now answers perfectly well, under a name this SMF did not address.
	poi.mu.Lock()
	poi.misname = wrongNE
	poi.mu.Unlock()

	pending := s.triggers.takeForWarrant(warrant.XID)
	if len(pending) != 1 {
		t.Fatalf("took %d withdrawals, want 1", len(pending))
	}

	rounds := 0
	s.triggers.sleep = func(time.Duration) {
		rounds++
		if rounds == 3 {
			// Once the mismatch is corrected the withdrawal completes, which is what
			// makes the retry worth having rather than merely persistent.
			poi.mu.Lock()
			poi.misname = ""
			poi.mu.Unlock()
		}
	}
	s.deactivate(pending)

	if rounds < 3 {
		t.Errorf("the withdrawal was retried %d times before succeeding, want at least 3 — an answer this element refuses must not be read as an acknowledgement", rounds)
	}
	if n := len(s.triggers.pending); n != 0 {
		t.Errorf("%d withdrawals still pending after the POI's answer became attributable, want 0", n)
	}
}

// TestAWithdrawalStuckOnOurOwnRefusalIsDistinguishable is task 3.9, and it is the
// one that decides whether an operator looks in the right place.
//
// A systematic validation mismatch is the failure mode this change introduces: the
// pending entry never clears, the retries never stop, and because pending entries
// keep their endpoint's keepalives flowing, the POI's own fail-safe cannot reclaim
// the tasking either. Both remedies are held open by the same condition. Reported
// only as taskingWithdrawalFailed, it presents as a POI that will not answer —
// while the POI is answering perfectly well and being disbelieved here.
func TestAWithdrawalStuckOnOurOwnRefusalIsDistinguishable(t *testing.T) {
	var mu sync.Mutex
	var reports []string
	admf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test
		mu.Lock()
		reports = append(reports, string(body))
		mu.Unlock()
		//nolint:errcheck // test handler write
		_, _ = w.Write([]byte(`<?xml version="1.0"?><X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">` +
			`<x1ResponseMessage><oK>AcknowledgedAndCompleted</oK></x1ResponseMessage></X1Response>`))
	}))
	defer admf.Close()

	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}
	s.reporter = x1.NewReporter(admf.URL, "admf", "smf", nil)

	warrant, trigger := installOneTrigger(t, s)

	poi.mu.Lock()
	poi.misname = wrongNE
	poi.mu.Unlock()

	pending := s.triggers.takeForWarrant(warrant.XID)

	rounds := 0
	s.triggers.sleep = func(time.Duration) {
		rounds++
		if rounds == 4 {
			poi.mu.Lock()
			poi.misname = ""
			poi.mu.Unlock()
		}
	}
	s.deactivate(pending)

	mu.Lock()
	defer mu.Unlock()
	var unattributable, failed int
	for _, body := range reports {
		if strings.Contains(body, x1.NEIssueX1ResponseUnattributable) {
			unattributable++
		}
		if strings.Contains(body, x1.NEIssueTaskingWithdrawalFailed) {
			failed++
		}
		// The same rule as every other NE-level report: which warrant, and whose
		// session, are not this channel's business.
		if strings.Contains(body, string(trigger)) || strings.Contains(body, string(warrant.XID)) {
			t.Errorf("an NE-level report names an identifier:\n%s", body)
		}
	}

	if unattributable == 0 {
		t.Error("a withdrawal refused by this element's own response binding was reported only as a POI failure; an operator is sent to look at a POI that is answering correctly")
	}
	if failed == 0 {
		t.Error("the withdrawal failure itself was not reported")
	}
	// The condition names the field that disagreed, which is the operator's first
	// clue and the difference between "fix your configuration" and "go and look at
	// the UPF".
	named := false
	for _, body := range reports {
		if strings.Contains(body, x1.NEIssueX1ResponseUnattributable) && strings.Contains(body, "neIdentifier") {
			named = true
		}
	}
	if !named {
		t.Error("the unattributable-answer report does not name which envelope field disagreed")
	}
}

// TestAnUnbindableActivationAnswerIsReportedAsElementLevel is the gap the
// end-to-end suite found, and the reason it is worth running a section against a
// real deployment even when the unit tests are green.
//
// The unattributable condition was wired into the withdrawal path only, because
// that is where this change's risk register put it. On the activation path the
// element reported a task issue and nothing else — the same report whether the POI
// refused the warrant or this element refused to believe the POI's answer. Those
// need opposite actions: one is a POI to go and look at, the other a configuration
// mismatch on this side.
//
// The task issue stays. On this path the element does know which warrant it was
// installing, so naming it is true and useful; what the task issue cannot convey
// is which side of the exchange is at fault.
func TestAnUnbindableActivationAnswerIsReportedAsElementLevel(t *testing.T) {
	var mu sync.Mutex
	var reports []string
	admf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body) //nolint:errcheck // test
		mu.Lock()
		reports = append(reports, string(body))
		mu.Unlock()
		//nolint:errcheck // test handler write
		_, _ = w.Write([]byte(`<?xml version="1.0"?><X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">` +
			`<x1ResponseMessage><oK>AcknowledgedAndCompleted</oK></x1ResponseMessage></X1Response>`))
	}))
	defer admf.Close()

	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	s.taskReporter = &recordingTaskReporter{}
	s.reporter = x1.NewReporter(admf.URL, "admf", "smf", nil)

	// The POI answers perfectly well, under a name this SMF did not address.
	poi.mu.Lock()
	poi.misname = wrongNE
	poi.mu.Unlock()

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	s.installFor("session-1", []types.InterceptTask{warrant},
		[]upfSession{{node: upfNode("10.0.1.5"), seid: 42}}, 7)

	// The X1 exchanges happen off the signalling path, so the assertion has to wait
	// for them rather than for installFor to return.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		seen := len(reports)
		mu.Unlock()
		if seen > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	var unattributable int
	for _, body := range reports {
		if strings.Contains(body, x1.NEIssueX1ResponseUnattributable) {
			unattributable++
		}
		if strings.Contains(body, x1.NEIssueX1ResponseUnattributable) &&
			strings.Contains(body, string(warrant.XID)) {
			t.Errorf("the element-level condition names a warrant:\n%s", body)
		}
	}
	if unattributable == 0 {
		t.Error("an activation answered by the wrong element was reported only as a task issue; an operator is sent to look at a POI that is answering correctly")
	}

	// And nothing was recorded as installed on the strength of an answer that
	// could not be bound.
	if n := len(s.triggers.installed); n != 0 {
		t.Errorf("%d triggers recorded as installed, want 0", n)
	}
}

// TestTriggerCarriesDeliveryXIDNotTaskXID: the trigger's ProductID is the label
// the POI puts on its xCC, and it has to be the label this element puts on its
// own xIRI for the same warrant — the ADMF's productID wherever it provisioned
// one. Sending the task XID instead is invisible in every deployment that does
// not use the field, because DeliveryXID() is then the task XID and both values
// are the same one; it separates the two streams the moment an agency does use
// it, and separates them silently, since each stream stays well-formed and
// individually deliverable. So the warrant here provisions a productID that
// differs from its XID: a test that leaves it unset passes against the defect.
func TestTriggerCarriesDeliveryXIDNotTaskXID(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)

	const (
		taskXID   = "11111111-1111-4111-8111-111111111111"
		productID = "22222222-2222-4222-8222-222222222222"
	)
	warrant := types.InterceptTask{
		XID:       taskXID,
		ProductID: productID,
		Products:  []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode("10.0.1.5"), seid: 0x2632898145f4d191}}

	planned, unreachable := s.triggers.plan("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	if len(unreachable) != 0 || len(planned) != 1 {
		t.Fatalf("plan() = %d triggers, %d unreachable; want 1, 0", len(planned), len(unreachable))
	}

	// Guards the test itself: if these ever coincide, the assertions below hold
	// against the defect too and prove nothing.
	if warrant.DeliveryXID() == warrant.XID {
		t.Fatal("test setup: the productID must differ from the task XID, or this test cannot detect the defect")
	}

	if got := planned[0].trigger.ProductID; got != warrant.DeliveryXID() {
		t.Errorf("trigger ProductID = %q, want the delivery XID %q — the POI labels its "+
			"xCC with this, and an MDF attributes on that label alone", got, warrant.DeliveryXID())
	}
	if got := planned[0].trigger.ProductID; got == types.XID(taskXID) {
		t.Errorf("trigger ProductID = %q, the task XID — content would carry a different "+
			"label from this element's own signalling for the same warrant", got)
	}

	// The X2 side of the same claim: lawfulintercept.go labels an xIRI header with
	// parseXID(t.DeliveryXID()), and the UPF labels its xCC header from the
	// trigger's ProductID. Comparing the two encoded headers is what says the
	// mediation function can join the streams.
	if x2, x3 := parseXID(warrant.DeliveryXID()), parseXID(planned[0].trigger.ProductID); x2 != x3 {
		t.Errorf("X2 header XID %x != X3 header XID %x — signalling and content would be "+
			"two unrelated intercepts to the mediation function", x2, x3)
	}

	// The registry still keys tasking by the warrant this element was tasked with:
	// how product is labelled is not how a withdrawal finds what to withdraw.
	if planned[0].warrant != types.XID(taskXID) {
		t.Errorf("registry warrant = %q, want the task XID %q", planned[0].warrant, taskXID)
	}
}

// withdrawOne installs a trigger and then withdraws it, returning the pending
// withdrawals deactivate was given. It is the shape every withdrawal test needs:
// a trigger the registry believes is installed, taken out of the registry the way
// a release does, so deactivate runs against a real entry rather than a literal.
func withdrawOne(t *testing.T, s *subsystem) []withdrawal {
	t.Helper()

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{node: upfNode("10.0.1.5"), seid: 0x2632898145f4d191}}

	planned, unreachable := s.triggers.plan("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	if len(unreachable) != 0 || len(planned) != 1 {
		t.Fatalf("plan() = %d triggers, %d unreachable; want 1, 0", len(planned), len(unreachable))
	}
	s.installTriggers(planned)

	pending := s.triggers.takeForSession("session-ref-1")
	if len(pending) != 1 {
		t.Fatalf("takeForSession returned %d withdrawals, want 1", len(pending))
	}

	return pending
}

// TestWithdrawalCompletesWhenPOIDoesNotHoldTheTask: 2020 is "XID does not exist
// on NE", and a POI is required to answer it for tasking it does not hold — after
// a restart, or after its own fail-safe purged what this element could no longer
// name. That is the withdrawal's goal reached, not a failure to reach it, and the
// retry loop must exit on it. Read as a failure it never exits: the answer cannot
// change, so the loop runs forever against a POI that is behaving correctly.
func TestWithdrawalCompletesWhenPOIDoesNotHoldTheTask(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	pending := withdrawOne(t, s)

	// The POI restarted between the install and the withdrawal: it no longer holds
	// the XID and says so.
	poi.mu.Lock()
	poi.refuse = true
	poi.refuseCode = 2020
	poi.mu.Unlock()

	s.deactivate(pending) // must return; against the defect this never terminates

	if n := poi.countMessages("DeactivateTaskRequest"); n != 1 {
		t.Errorf("DeactivateTaskRequest count = %d, want 1 — an answer of 2020 cannot "+
			"change on a retry, so retrying it is a loop with no exit", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after the POI said it does not hold the task, want 0 — "+
			"the entry that never clears is what raises taskingWithdrawalStuck against "+
			"an interception that has already stopped", n)
	}
}

// TestWithdrawalStillRetriesOtherFailures keeps the reclassification narrow: only
// 2020 means the tasking is gone. Any other refusal is a POI that still holds the
// trigger and has not agreed to drop it, which is the case the pending state and
// the retry loop exist for.
func TestWithdrawalStillRetriesOtherFailures(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	pending := withdrawOne(t, s)

	poi.mu.Lock()
	poi.refuse = true
	poi.refuseCode = 1000
	poi.mu.Unlock()

	// The backoff is the registry's, not this test's: drive it through the clock
	// hook so the retries happen at once. Sleeping for real here would assert the
	// same thing thirty-five seconds later.
	s.triggers.sleep = func(time.Duration) {
		if poi.countMessages("DeactivateTaskRequest") >= 3 {
			poi.mu.Lock()
			poi.refuse = false
			poi.mu.Unlock()
		}
	}

	s.deactivate(pending)

	if n := poi.countMessages("DeactivateTaskRequest"); n < 2 {
		t.Errorf("DeactivateTaskRequest count = %d, want at least 2 — a refusal that is "+
			"not 2020 leaves the POI holding the trigger, and must be retried", n)
	}
	if n := s.triggers.pendingCount(); n != 0 {
		t.Errorf("pending = %d after the POI finally acknowledged, want 0", n)
	}
}

// TestKeepaliveLapsesAfterNoSuchTaskWithdrawal: the second half of what a stuck
// pending entry costs. A triggering function keeps a POI alive while it believes
// that POI holds tasking it installed, so an entry that can never clear keeps the
// keepalives flowing — and those keepalives are exactly what stops that POI's own
// fail-safe from reclaiming orphaned tasking. Completing the withdrawal on 2020
// is what lets the endpoint go quiet and the backstop work.
func TestKeepaliveLapsesAfterNoSuchTaskWithdrawal(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	pending := withdrawOne(t, s)

	endpoint := s.triggers.endpoints["10.0.1.5"]
	endpoint.markReconciled()
	if !s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Fatal("test setup: the endpoint should be kept alive while a withdrawal is pending")
	}

	poi.mu.Lock()
	poi.refuse = true
	poi.refuseCode = 2020
	poi.mu.Unlock()

	s.deactivate(pending)

	if s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Error("the endpoint is still being kept alive after a completed withdrawal — " +
			"the keepalives a phantom pending entry earns are what disable the POI's fail-safe")
	}
}

// TestSessionTeardownLeavesNoTaskingBehind pins the contract the teardown paths
// depend on: taking a session's triggers out of the registry and withdrawing them
// leaves this element answerable for nothing at that POI, so it stops sending
// keepalives and the POI's own fail-safe becomes reachable again.
//
// This is what a teardown path that forgets to call UntriggerCC costs. Not the
// missing release record — that one an operator could at least notice — but a
// trigger that stays installed, keeping the keepalives flowing, which is exactly
// what stops the POI's fail-safe from reclaiming it. Interception then outlives
// the session that authorised it with every party behaving as designed.
func TestSessionTeardownLeavesNoTaskingBehind(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi)
	pending := withdrawOne(t, s)

	endpoint := s.triggers.endpoints["10.0.1.5"]
	endpoint.markReconciled()
	if !s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Fatal("test setup: a session holding a trigger should keep its POI alive")
	}

	s.deactivate(pending)

	if n := len(s.triggers.installed); n != 0 {
		t.Errorf("%d triggers still installed after the session's teardown, want 0", n)
	}
	if s.triggers.keepaliveDue("10.0.1.5", endpoint) {
		t.Error("the POI is still being kept alive after the session that held its " +
			"tasking was torn down — its fail-safe cannot reclaim anything while this " +
			"element keeps telling it that the function responsible is present")
	}
}
