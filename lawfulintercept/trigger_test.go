// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	smfctx "github.com/omec-project/smf/context"
)

// upfNode parses a UPF's N4 node identity the way the session path carries it —
// unresolved, so a test can distinguish matching by identity from matching by
// address (see matchEndpoint).
func upfNode(s string) smfctx.NodeID { return *smfctx.NewNodeID(s) }

// mustRegistry builds a registry from a configuration the test knows is valid.
// Construction only fails on an ambiguous configuration, which the tests that care
// about that assert on explicitly.
func mustRegistry(cfg Config) *triggerRegistry {
	reg, err := newTriggerRegistry(cfg, nil)
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

			//nolint:errcheck // test handler write
			_, _ = w.Write([]byte(`<?xml version="1.0"?><x1:X1Response xmlns:x1="http://uri.etsi.org/03221/X1/2017/10">` +
				`<x1:x1ResponseMessage>` + details + `<x1:oK>AcknowledgedAndCompleted</x1:oK>` +
				`</x1:x1ResponseMessage></x1:X1Response>`))

			return
		}

		if refuse {
			//nolint:errcheck // test handler write
			_, _ = w.Write([]byte(`<?xml version="1.0"?><X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10">` +
				`<x1ResponseMessage><errorInformation><errorCode>1000</errorCode>` +
				`<errorDescription>refused</errorDescription></errorInformation></x1ResponseMessage></X1Response>`))

			return
		}

		//nolint:errcheck // test handler write
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
func triggerSubsystem(poi *fakePOI) *subsystem {
	cfg := Config{
		NEID: "smf-1",
		MDF3: "10.0.60.122:42069",
		UPFTriggers: []UPFTrigger{
			{NodeID: "10.0.1.5", X1URL: poi.srv.URL, NEID: "upf-1"},
		},
	}

	return &subsystem{
		neID:     "smf-1",
		triggers: mustRegistry(cfg),
	}
}

// TestInstallTriggersSendsWarrantIdentity is the core of task 10.6: the trigger a
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
		MDF3: "10.0.60.122:42069",
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

	s := triggerSubsystem(poi)
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

func (r *recordingTaskReporter) NotifyTask(xid, reportType, details string) {
	r.reports = append(r.reports, taskReport{xid, reportType, details})
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
// (this SMF is alive and sending keepalives) would both never reach. Tasking
// nobody can withdraw is exactly what must not exist, so the install must notice
// and take it down itself.
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
	if byNode := s.triggers.takeForSession("session-ref-1"); len(byNode) != 1 {
		t.Fatalf("takeForSession returned %d UPFs, want 1", len(byNode))
	}

	s.installTriggers(planned)

	if n := poi.countMessages("ActivateTaskRequest"); n != 1 {
		t.Fatalf("ActivateTaskRequest count = %d, want 1", n)
	}
	if n := poi.countMessages("DeactivateTaskRequest"); n != 1 {
		t.Errorf("DeactivateTaskRequest count = %d, want 1 — a trigger installed after "+
			"its session was released must be withdrawn by the install itself", n)
	}
	if !strings.Contains(strings.Join(poi.sent(), ""), string(planned[0].trigger.XID)) {
		t.Error("the withdrawal did not name the trigger that was installed")
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

// ── Matching a session's UPF to its triggering endpoint (review R45) ──
//
// These four cover the CC-TF's join between two independently configured things:
// the UPF named in li.upfTriggers, and the UPF actually serving a session. Getting
// it wrong is invisible from outside the SMF — the warrant stays active, the
// datapath keeps duplicating, and the content is dropped as unattributable — so
// each of these asserts a property that produced silence rather than an error.

// TestMatchEndpointFollowsAUPFThatChangesAddress is R45's regression test. The
// registry used to store the address its configured NodeID resolved to at
// construction, which froze a value that moves: recreating the UPF's Service gave
// it a new address, the session path followed within the minute (the SMF refreshes
// its DNS cache on a ticker) and the registry did not, so every CC warrant for that
// UPF reported "no triggering endpoint" until the SMF was restarted.
func TestMatchEndpointFollowsAUPFThatChangesAddress(t *testing.T) {
	const name = "upf-moving.test"
	smfctx.InsertDnsHostIp(name, net.ParseIP("10.0.1.5"))

	reg := mustRegistry(Config{
		NEID: "smf-1", MDF3: "10.0.60.122:42069",
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
		NEID: "smf-1", MDF3: "10.0.60.122:42069",
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
		NEID: "smf-1", MDF3: "10.0.60.122:42069",
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

// TestTriggerRegistryRejectsAmbiguousNode covers the silent half of R45. Two
// entries naming one node used to collapse into a single registry entry, the second
// overwriting the first, so a two-UPF configuration presented as a one-UPF registry
// and the displaced UPF's content was never attributable — with nothing logged and
// no fault raised.
func TestTriggerRegistryRejectsAmbiguousNode(t *testing.T) {
	_, err := newTriggerRegistry(Config{
		NEID: "smf-1", MDF3: "10.0.60.122:42069",
		UPFTriggers: []UPFTrigger{
			{NodeID: "10.0.1.5", X1URL: "https://upf-1:8443/X1/NE", NEID: "upf-1"},
			{NodeID: "10.0.1.5", X1URL: "https://upf-2:8443/X1/NE", NEID: "upf-2"},
		},
	}, nil)
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
		NEID: "smf-1", MDF3: "10.0.60.122:42069",
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
