// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
)

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
}

func newFakePOI(t *testing.T) *fakePOI {
	t.Helper()

	p := &fakePOI{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		p.mu.Lock()
		p.bodies = append(p.bodies, string(body))
		p.requests++
		refuse := p.refuse
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
			p.mu.Unlock()

			var details string
			for _, xid := range held {
				details += `<x1:taskResponseDetails><x1:taskDetails><x1:xId>` + xid +
					`</x1:xId></x1:taskDetails><x1:taskStatus>Active</x1:taskStatus></x1:taskResponseDetails>`
			}

			_, _ = w.Write([]byte(`<?xml version="1.0"?><x1:X1Response xmlns:x1="http://uri.etsi.org/03221/X1/2017/10">` +
				`<x1:x1ResponseMessage>` + details + `<x1:oK>AcknowledgedAndCompleted</x1:oK>` +
				`</x1:x1ResponseMessage></x1:X1Response>`))

			return
		}

		if refuse {
			_, _ = w.Write([]byte(`<?xml version="1.0"?><X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">` +
				`<x1ResponseMessage><errorInformation><errorCode>1000</errorCode>` +
				`<errorDescription>refused</errorDescription></errorInformation></x1ResponseMessage></X1Response>`))

			return
		}

		_, _ = w.Write([]byte(`<?xml version="1.0"?><X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">` +
			`<x1ResponseMessage><oK>AcknowledgedAndCompleted</oK></x1ResponseMessage></X1Response>`))
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
func triggerSubsystem(poi *fakePOI, nodeID string) *subsystem {
	cfg := Config{
		NEID: "smf-1",
		MDF3: "10.0.60.122:42069",
		UPFTriggers: []UPFTrigger{
			{NodeID: nodeID, X1URL: poi.srv.URL, NEID: "upf-1"},
		},
	}

	return &subsystem{
		neID:     "smf-1",
		triggers: newTriggerRegistry(cfg, nil),
	}
}

// TestInstallTriggersSendsWarrantIdentity is the core of task 10.6: the trigger a
// CC-TF sends must carry the warrant XID, the session's correlation identifier and
// the UPF's own SEID as the detection criterion, and must be preceded by the
// destination it references.
func TestInstallTriggersSendsWarrantIdentity(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi, "10.0.1.5")

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}

	s.installTriggers("session-ref-1",
		[]types.InterceptTask{warrant},
		[]upfSession{{nodeID: "10.0.1.5", seid: 14426627323429955319}},
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
	s := triggerSubsystem(poi, "10.0.1.5")

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{nodeID: "10.0.1.5", seid: 42}}

	s.installTriggers("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)
	s.installTriggers("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

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
		MDF3: "10.0.60.122:42069",
		UPFTriggers: []UPFTrigger{
			{NodeID: "10.0.1.5", X1URL: poi.srv.URL, NEID: "upf-1"},
			{NodeID: "10.0.1.6", X1URL: poi.srv.URL, NEID: "upf-2"},
		},
	}
	s := &subsystem{neID: "smf-1", triggers: newTriggerRegistry(cfg, nil)}

	warrants := []types.InterceptTask{
		{XID: "11111111-1111-4111-8111-111111111111", Products: []types.ProductType{types.ProductCC}},
		{XID: "22222222-2222-4222-8222-222222222222", Products: []types.ProductType{types.ProductCC}},
	}
	upfs := []upfSession{{nodeID: "10.0.1.5", seid: 42}, {nodeID: "10.0.1.6", seid: 43}}

	s.installTriggers("session-ref-1", warrants, upfs, 7)

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

	s := triggerSubsystem(poi, "10.0.1.5")
	rec := &recordingTaskReporter{}
	s.taskReporter = rec

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}

	s.installTriggers("session-ref-1", []types.InterceptTask{warrant},
		[]upfSession{{nodeID: "10.0.1.5", seid: 42}}, 7)

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

	s := triggerSubsystem(poi, "10.0.1.5")
	s.taskReporter = &recordingTaskReporter{}

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	upfs := []upfSession{{nodeID: "10.0.1.5", seid: 42}}

	s.installTriggers("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

	if len(s.triggers.installed) != 0 {
		t.Fatalf("a refused trigger was recorded as installed: %+v", s.triggers.installed)
	}

	poi.mu.Lock()
	poi.refuse = false
	poi.mu.Unlock()

	s.installTriggers("session-ref-1", []types.InterceptTask{warrant}, upfs, 7)

	if len(s.triggers.installed) != 1 {
		t.Errorf("installed = %d after a successful retry, want 1", len(s.triggers.installed))
	}
}

// TestInstallTriggersReportsMissingEndpoint covers a UPF carrying a tasked
// session's traffic that this SMF has no way to task. The interception is
// authorised and will produce nothing, so it must not pass silently.
func TestInstallTriggersReportsMissingEndpoint(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi, "10.0.1.5")
	rec := &recordingTaskReporter{}
	s.taskReporter = rec

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}

	// A UPF absent from the configured triggering endpoints.
	s.installTriggers("session-ref-1", []types.InterceptTask{warrant},
		[]upfSession{{nodeID: "10.0.9.9", seid: 42}}, 7)

	if poi.requests != 0 {
		t.Error("a request was sent for a UPF with no configured endpoint")
	}
	if len(rec.reports) != 1 {
		t.Fatalf("task issues reported = %d, want 1", len(rec.reports))
	}
}

// TestTakeForSessionAndWarrant pins the bookkeeping the deactivation paths depend
// on. A session's triggers are withdrawn when it is released; a warrant's are
// withdrawn when it is deactivated, wherever they were installed.
func TestTakeForSessionAndWarrant(t *testing.T) {
	reg := &triggerRegistry{installed: map[string]types.XID{}}

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
	total := 0
	for node, xids := range got {
		if node != "10.0.1.5" && node != "10.0.1.6" {
			t.Errorf("takeForSession grouped under an unexpected node %q", node)
		}
		total += len(xids)
	}
	if total != 4 {
		t.Errorf("takeForSession returned %d triggers, want 4 (2 warrants x 2 UPFs)", total)
	}
	if len(reg.installed) != 4 {
		t.Errorf("installed = %d after takeForSession, want 4 (sess-2's)", len(reg.installed))
	}

	// Deactivating a warrant takes its remaining triggers, grouped by UPF so each
	// can be deactivated at the right peer.
	byNode := reg.takeForWarrant("warrant-a")
	total = 0
	for node, xids := range byNode {
		if node != "10.0.1.5" && node != "10.0.1.6" {
			t.Errorf("takeForWarrant grouped under an unexpected node %q", node)
		}
		total += len(xids)
	}
	if total != 2 {
		t.Errorf("takeForWarrant returned %d triggers, want warrant-a's remaining 2", total)
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

// TestInstallTriggersReprovisionsAfterRestart is review R37: a POI restarts
// independently of this triggering function and takes the destination we
// provisioned with it. Believing otherwise meant every later trigger named a
// destination the POI no longer knew, so it duplicated the subject's traffic and
// discarded every copy while we were told interception was running.
func TestInstallTriggersReprovisionsAfterRestart(t *testing.T) {
	poi := newFakePOI(t)
	s := triggerSubsystem(poi, "10.0.1.5")
	s.taskReporter = &recordingTaskReporter{}

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}

	// First session: destination provisioned, trigger accepted.
	s.installTriggers("session-1", []types.InterceptTask{warrant},
		[]upfSession{{nodeID: "10.0.1.5", seid: 42}}, 7)

	if n := poi.countMessages("CreateDestinationRequest"); n != 1 {
		t.Fatalf("CreateDestination sent %d times, want 1", n)
	}

	// The POI restarts: it has forgotten the destination, so it now refuses a
	// trigger naming it — which is the only way we can find out.
	poi.mu.Lock()
	poi.refuseUntilProvisioned = true
	poi.mu.Unlock()

	s.installTriggers("session-2", []types.InterceptTask{warrant},
		[]upfSession{{nodeID: "10.0.1.5", seid: 43}}, 9)

	// We must have re-provisioned rather than given up.
	if n := poi.countMessages("CreateDestinationRequest"); n != 2 {
		t.Errorf("CreateDestination sent %d times, want a second after the refusal", n)
	}

	// And the interception must now be installed, not abandoned.
	if len(s.triggers.installed) != 2 {
		t.Errorf("installed = %d, want both sessions tasked after the retry", len(s.triggers.installed))
	}
}

// TestReconcileWithdrawsTaskingFromAPreviousLife is review R40: after a restart
// this process has no record of the triggers it installed, while the POI still
// holds them — and tasking nobody can withdraw does not stop, not even when the
// warrant is revoked. The keepalive fail-safe cannot cover it, because a restarted
// triggering function is alive.
func TestReconcileWithdrawsTaskingFromAPreviousLife(t *testing.T) {
	poi := newFakePOI(t)
	poi.mu.Lock()
	poi.holds = []string{"aaaaaaaa-1111-4111-8111-111111111111", "bbbbbbbb-2222-4222-8222-222222222222"}
	poi.mu.Unlock()

	s := triggerSubsystem(poi, "10.0.1.5")
	s.taskReporter = &recordingTaskReporter{}

	s.reconcileTriggers()

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
	s := triggerSubsystem(poi, "10.0.1.5")
	s.taskReporter = &recordingTaskReporter{}

	warrant := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Products: []types.ProductType{types.ProductCC},
	}
	s.installTriggers("session-1", []types.InterceptTask{warrant},
		[]upfSession{{nodeID: "10.0.1.5", seid: 42}}, 7)

	// The POI reports exactly what this process just installed.
	var mine []string
	for _, xid := range s.triggers.installed {
		mine = append(mine, string(xid))
	}

	poi.mu.Lock()
	poi.holds = mine
	poi.mu.Unlock()

	s.reconcileTriggers()

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

func (r *recordingTaskReporter) ReportTaskIssue(xid, reportType, details string) error {
	r.reports = append(r.reports, taskReport{xid, reportType, details})

	return nil
}
