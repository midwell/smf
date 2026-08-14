// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	smfctx "github.com/omec-project/smf/context"
)

// The SMF is the CC Triggering Function. Marking a session's FARs for duplication
// tells the UPF *to* copy packets; it does not tell it whose warrant the copies
// belong to, and a mediation function attributes product by XID alone. TS 33.128
// clause 6.2.3.3 closes that gap with LI_T3: the CC-TF tasks the CC-POI in the UPF
// over ETSI TS 103 221-1, acting in the "ADMF" role, and supplies the warrant XID
// (as ProductID), the correlation identifier it uses on that session's own xIRI,
// the packet detection criteria, and the X3 destination.
//
// Duplication and tasking therefore travel over different interfaces
// and are applied at slightly different moments — see triggerCC on the window
// between them.

// UPFTrigger names one UPF's LI_T3 triggering endpoint. The trigger must reach the
// UPF *serving the session*, and a session may be served by several, so these are
// configured per UPF and resolved by the N4 node address.
type UPFTrigger struct {
	// NodeID identifies the UPF's N4 node. It may be given exactly as the slice
	// topology names it, in which case it matches by identity and no name
	// resolution happens at all; or as any name or address that resolves to the
	// same node, which is matched by resolving both at the moment of use. A DNS
	// name is preferred over a deploy-time ClusterIP. See matchEndpoint.
	NodeID string
	// X1URL is that UPF's LI_T3 endpoint, e.g. https://upf-1:8443/X1/NE.
	X1URL string
	// NEID is the identifier the UPF answers to on X1, which its certificate is
	// bound to. It cannot be derived from the URL, which is why these are listed
	// explicitly rather than built from the N4 address and a port.
	NEID string
}

// upfEndpoint is the CC-TF's client for one UPF, plus the delivery destination it
// has provisioned there.
type upfEndpoint struct {
	req *x1.Requester
	did string
	// node is the configured NodeID, parsed. Held so a session's serving UPF can be
	// matched by identity before anything is resolved (matchEndpoint).
	node smfctx.NodeID

	mu sync.Mutex
	// destinationReady records that CreateDestination succeeded, since a trigger
	// referencing an unprovisioned DID resolves to no destination at the POI
	// (TS 33.128 table 6.2.3-6: destinations are configured "prior to first use").
	destinationReady bool
}

// triggerRegistry holds the CC-TF's per-UPF endpoints and the trigger tasks it has
// installed.
type triggerRegistry struct {
	mdf3 string
	// endpoints is keyed by the NodeID *as configured*, never by an address derived
	// from it: the configured string is stable for the life of the process, so a
	// trigger installed at a UPF is still found under the same key when it is
	// withdrawn, even if that UPF's address changed in between. Written once during
	// construction and read-only afterwards, so it needs no lock.
	endpoints map[string]*upfEndpoint
	// order is endpoints' keys, sorted, so matching iterates deterministically. Two
	// configured nodes can resolve to one address — transiently, while a Service is
	// being recreated, or permanently in a mistaken configuration — and choosing
	// between them by Go's map order would send a session's triggers to a different
	// UPF from one establishment to the next. The final review found that same
	// nondeterminism in warrant selection at the CC-POI; it is worse here, because
	// the trigger carries the X3 destination.
	order []string

	mu sync.Mutex
	// installed maps a (warrant, session, UPF) triple to the XID this CC-TF
	// allocated for that trigger. The trigger's XID is the CC-TF's own — the
	// warrant's travels in ProductID — and must stay stable from activation to
	// deactivation, so it is remembered rather than recomputed.
	installed map[string]types.XID
}

// liKeepaliveInterval is how often each triggered POI is told this triggering
// function is still here.
//
// It must be comfortably shorter than the POI's own fail-safe window, since that
// window is what protects against a triggering function that has died: too slow
// and healthy tasking lapses, too fast and it costs a needless request. The POI's
// timeout is its own configuration, so this is deliberately well inside any
// sensible value rather than derived from it.
const liKeepaliveInterval = 60 * time.Second

// newTriggerRegistry builds the CC-TF's endpoints from configuration. A UPF with
// no configured triggering endpoint cannot be tasked, so CC for a session it
// serves is reported as a fault rather than silently skipped.
func newTriggerRegistry(cfg Config, clientTLS *tls.Config) (*triggerRegistry, error) {
	reg := &triggerRegistry{
		mdf3:      cfg.MDF3,
		endpoints: make(map[string]*upfEndpoint, len(cfg.UPFTriggers)),
		installed: make(map[string]types.XID),
	}
	for _, t := range cfg.UPFTriggers {
		// Key by the NodeID exactly as configured, and resolve nothing here. An
		// earlier version keyed by the address the NodeID resolved to at this moment,
		// which made a derived, mutable value permanent: a UPF that later changed
		// address was never found again, and a name that did not resolve at the
		// instant the SMF started was keyed "0.0.0.0" for the life of the process.
		// Either way every CC warrant for that UPF reported "no triggering endpoint"
		// until the SMF was restarted. Matching now happens per use, in
		// matchEndpoint.
		if _, dup := reg.endpoints[t.NodeID]; dup {
			// Previously the second entry silently replaced the first, so a
			// two-UPF configuration presented as a one-UPF registry and the
			// displaced UPF's content was never attributable.
			return nil, fmt.Errorf("upfTriggers names the same node twice: %q", t.NodeID)
		}
		reg.endpoints[t.NodeID] = &upfEndpoint{
			node: *smfctx.NewNodeID(t.NodeID),
			req:  x1.NewRequester(t.X1URL, cfg.NEID, t.NEID, clientTLS),
			// One destination per UPF, named by a DID this CC-TF allocates.
			did: x1.NewUUID(),
		}
		reg.order = append(reg.order, t.NodeID)
	}
	slices.Sort(reg.order)

	go reg.keepalive()

	return reg, nil
}

// matchEndpoint finds the triggering endpoint for the UPF serving a session.
//
// Identity is tried first and costs nothing: when `li.upfTriggers` names the node
// the way the slice topology names it, the two NodeIDs are equal and no name is
// ever resolved. That is upstream's own conclusion for the sibling comparison in
// nodeInLinks (#613) — membership is identity, not reachability.
//
// Resolution remains as the fallback because these two values come from
// *independent* configuration — the LI block and the slice topology — and need not
// agree: a DNS name in the LI block has to match a session whose N4 node is an IP,
// which is the case that made resolution necessary in the first place. So identity
// alone cannot replace it, and address matching alone was what broke.
//
// What matters is *when* this resolves, not whether: at the point of use
// rather than once at construction. That is what makes a recreated Service, or a
// name that was not yet resolvable at startup, recover on its own instead of
// requiring an SMF restart. It is also cheap here — the trigger path runs a few
// times per session, an IP literal short-circuits without touching DNS, and a name
// reads the SMF's DNS cache that a 60-second refresh keeps current.
//
// An unresolvable node NEVER matches. Failed resolution yields net.IPv4zero, so
// comparing it would make every unresolvable name equal to every other — precisely
// the defect #613 fixed for gNB names, which here would task one UPF's CC-POI with
// another UPF's warrant. Returning "no match" instead means the warrant is reported
// to the LIPF as having no triggering endpoint, which is true and actionable.
func (r *triggerRegistry) matchEndpoint(session smfctx.NodeID) (string, *upfEndpoint, bool) {
	for _, key := range r.order {
		if ep := r.endpoints[key]; ep.node.Equal(session) {
			return key, ep, true
		}
	}

	want := session.ResolveNodeIdToIp()
	if want.Equal(net.IPv4zero) {
		return "", nil, false
	}
	for _, key := range r.order {
		if ep := r.endpoints[key]; ep.node.ResolveNodeIdToIp().Equal(want) {
			return key, ep, true
		}
	}

	return "", nil, false
}

// keepalive tells every triggered POI, periodically, that this triggering function
// is still present — which is what lets a POI safely purge tasking when it is not.
// Failures are ignored here: a POI that cannot be reached will lapse its own
// tasking, which is the outcome intended, and the trigger path reports the fault
// when it next tries to task it.
func (r *triggerRegistry) keepalive() {
	ticker := time.NewTicker(liKeepaliveInterval)
	defer ticker.Stop()

	for range ticker.C {
		for _, endpoint := range r.endpoints {
			// Best-effort: a missed keepalive is transient, and a POI that has really
			// gone away trips its own fail-safe; nothing here to act on per tick.
			//nolint:errcheck // periodic keepalive; a single miss is not actionable
			_ = endpoint.req.Keepalive()
		}
	}
}

// reconcileTriggers withdraws tasking a POI still holds from a previous life of
// this process.
//
// This is the case the keepalive fail-safe cannot cover. That fail-safe protects
// against a triggering function that is *gone*; one that has *restarted* is
// present, resumes keepalives within the minute, and so leaves behind triggers
// belonging to warrants the new process knows nothing about — and therefore can
// never withdraw, not even when the warrant is revoked.
//
// Withdrawing everything found is safe because of the authorisation model, not by
// assumption: a POI accepts tasking from exactly one triggering function
// (x1.WithADMF at the POI), so whatever it holds came from this one. **If a POI is
// ever allowed more than one triggering function, this needs provenance instead.**
//
// Run once, at startup, off the caller's goroutine: it is network I/O against every
// configured POI, and nothing else waits on it.
func (s *subsystem) reconcileTriggers() {
	if s.triggers == nil {
		return
	}

	for _, endpoint := range s.triggers.endpoints {
		reported, err := endpoint.req.ReportedTasks()
		if err != nil {
			// The POI may simply not be up yet — on a whole-cluster restart it very
			// likely is not. Worth telling the LIPF either way, because tasking may
			// have been left behind that this process cannot withdraw. Reported as an
			// element-level issue, not a task one: a task report has to name an XID,
			// and which warrants they were is precisely what was lost.
			if s.reporter != nil {
				s.reporter.Notify(x1.NEIssueReconcileFailed,
					"could not establish what content tasking a UPF still holds after restart")
			}

			continue
		}

		for _, task := range reported {
			xid := types.XID(task.TaskDetails.XID)
			if xid == "" {
				continue
			}

			// Skip anything this process has itself installed. Reconciliation runs
			// concurrently with ordinary triggering, so a session establishing right
			// now would otherwise have its brand-new trigger withdrawn by the cleanup.
			if s.triggers.holds(xid) {
				// It is ours, so it is not stale — but the POI's account of it is the
				// only way this function learns that a trigger it installed is not
				// actually running. A failed provisioning or an unresolved fault means
				// content interception has stopped while the warrant is live, which is
				// precisely what a CC triggering function exists to notice. The reply
				// was previously read for XIDs and nothing else.
				if !task.TaskStatus.Healthy() && s.reporter != nil {
					s.reporter.Notify(x1.NEIssueTriggerFaulty,
						"a UPF reports a content trigger this SMF installed as not running: "+
							task.TaskStatus.Describe())
				}

				continue
			}

			// Nothing here knows about this one, which after a restart means all of
			// it. Withdrawing is the only way it ever stops.
			//nolint:errcheck // best-effort withdrawal; a stale trigger that resists is covered by the reconcile fault report
			_ = endpoint.req.DeactivateTask(xid)
		}
	}
}

// upfSession is one UPF serving a session, with the detection criterion for that
// UPF's share of it.
type upfSession struct {
	// node is the serving UPF's N4 NodeID as the session carries it, passed on
	// unresolved so matchEndpoint can compare identities before addresses.
	node smfctx.NodeID
	// seid is the F-SEID the UPF assigned to this session — the value it tags onto
	// every packet it duplicates, and therefore the criterion that lets it match a
	// copy to this trigger. It is per UPF, unlike the correlation identifier.
	seid uint64
}

// sessionUPFs returns the UPFs serving sc, each with the SEID it assigned. Caller
// holds sc.SMLock (it reads sc.Tunnel and sc.PFCPContext).
func sessionUPFs(sc *smfctx.SMContext) []upfSession {
	if sc.Tunnel == nil {
		return nil
	}

	var out []upfSession
	seen := make(map[string]bool)

	for _, dp := range sc.Tunnel.DataPathPool {
		for node := dp.FirstDPNode; node != nil; node = node.Next() {
			if node.UPF == nil {
				continue
			}
			// The PFCP context is keyed by the resolved address because that is how the
			// SMF keys it everywhere (context/sm_context.go), so this lookup — and the
			// dedupe that goes with it — has to use the same form. Only the value
			// handed onward is the unresolved NodeID: matching a UPF to its triggering
			// endpoint is this package's business, and doing it on an address frozen
			// anywhere is the defect this avoids.
			key := node.UPF.NodeID.ResolveNodeIdToIp().String()
			if seen[key] {
				continue
			}
			pfcpCtx, ok := sc.PFCPContext[key]
			if !ok || pfcpCtx == nil || pfcpCtx.RemoteSEID == 0 {
				// The PFCP session is not established on this UPF yet, so it has no
				// SEID to match on. Nothing to trigger — the establishment response
				// for that UPF will bring us back here.
				continue
			}
			seen[key] = true
			out = append(out, upfSession{node: node.UPF.NodeID, seid: pfcpCtx.RemoteSEID})
		}
	}
	return out
}

// TriggerCC installs the LI_T3 triggers for sc at every UPF serving it, for each
// active task that wants CC. Call it once the UPF has answered the PFCP Session
// Establishment Request — the trigger's detection criterion is the SEID that
// response assigns, exactly as ReportEstablishment needs it for the correlation
// identifier. No-op and silent when LI is inactive or sc is untasked.
// Caller holds sc.SMLock.
func TriggerCC(sc *smfctx.SMContext) {
	if sub := active.Load(); sub != nil && sc != nil {
		sub.triggerCC(sc)
	}
}

// UntriggerCC removes the LI_T3 triggers installed for sc. Call it when the
// session is released (TS 33.128 clause 6.2.3.3.1). Caller holds sc.SMLock.
func UntriggerCC(sc *smfctx.SMContext) {
	if sub := active.Load(); sub != nil && sc != nil {
		sub.untriggerCC(sc)
	}
}

// triggerCC tasks each serving UPF's CC-POI for each CC warrant covering sc.
//
// The X1 exchange runs in a goroutine: it is a synchronous HTTPS round trip, and
// the caller holds sc.SMLock on the PDU-session signalling path, where a slow or
// unreachable peer must never block.
//
// That leaves a brief window at establishment in which the UPF is already
// duplicating (the DUPL FAR rode out with the establishment *request*) but is not
// yet tasked (the trigger needs the SEID from the *response*). Content in that
// window is dropped and reported by the CC-POI rather than delivered with an
// unattributable XID — the fail-closed choice, and the reason the window is
// acceptable rather than merely tolerated. It cannot be closed by reordering:
// the criterion the POI matches on does not exist until the response arrives.
//
// Caller holds sc.SMLock.
func (s *subsystem) triggerCC(sc *smfctx.SMContext) {
	if s.triggers == nil {
		return
	}

	var tasks []types.InterceptTask
	for _, t := range s.matchingTasks(sc) {
		if t.WantsProduct(types.ProductCC) {
			tasks = append(tasks, t)
		}
	}
	if len(tasks) == 0 {
		return
	}

	upfs := sessionUPFs(sc)
	if len(upfs) == 0 {
		return
	}

	// The correlation identifier is the session's, not the UPF's: it is the value
	// this SMF puts on the session's xIRI, so every UPF serving the session must
	// stamp the same one for the MDF to join content to signalling.
	// Only the detection criterion is per UPF.
	planned, unreachable := s.triggers.plan(sc.Ref, tasks, upfs, servingUPFSEID(sc))

	// A UPF we have no triggering endpoint for is carrying a tasked session's
	// traffic and cannot be told whose warrant it serves. The interception is
	// authorised and will produce nothing, which only the LIPF can resolve.
	for _, warrant := range unreachable {
		s.reportTaskIssue(warrant, "no triggering endpoint configured for a UPF serving the target")
	}

	if len(planned) == 0 {
		return
	}

	go s.installTriggers(planned)
}

// installTriggers performs the X1 exchanges off the signalling path. Every
// trigger it is given has already been claimed in the registry by triggerCC, so
// the withdrawal path can see it even before it exists at the POI.
func (s *subsystem) installTriggers(planned []plannedTrigger) {
	for _, p := range planned {
		if err := s.ensureDestination(p.endpoint); err != nil {
			s.triggers.release(p.key)
			s.reportTaskIssue(p.warrant, "X3 delivery destination could not be provisioned at the UPF")

			continue
		}

		err := p.endpoint.req.ActivateTask(p.trigger)
		if err != nil {
			// A refusal may mean the POI has lost the destination we provisioned —
			// it restarts independently of us, and its destinations do not survive
			// that. Re-provision and try once more before concluding the
			// interception cannot be arranged: the alternative is content dropped
			// at the POI for as long as this process happens to live.
			p.endpoint.forgetDestination()

			if again := s.ensureDestination(p.endpoint); again == nil {
				err = p.endpoint.req.ActivateTask(p.trigger)
			}
		}

		if err != nil {
			// Drop the bookkeeping so a later establishment or modification
			// retries, and tell the LIPF this warrant is producing no content.
			s.triggers.release(p.key)
			s.reportTaskIssue(p.warrant, "the UPF refused or failed the content-interception trigger")

			continue
		}

		// The session may have been released, or the warrant withdrawn, in the time
		// this trigger took to install. That withdrawal ran against a registry entry
		// whose trigger did not yet exist at the POI, so whatever it sent was refused
		// and the trigger is now in place with nothing tracking it: reconciliation
		// runs only at startup, and the POI's fail-safe only fires once this SMF
		// stops answering it, so nothing would ever take it down. Withdraw it here.
		if !s.triggers.stillHolds(p.key, p.trigger.XID) {
			//nolint:errcheck // best-effort withdrawal; the POI's fail-safe is the last resort
			_ = p.endpoint.req.DeactivateTask(p.trigger.XID)
		}
	}
}

// untriggerCC removes every trigger installed for sc, across warrants and UPFs.
//
// The UPFs are taken from this CC-TF's own bookkeeping rather than from the
// session, because by release time the session's PFCP state may already be gone —
// and a trigger we failed to find here is one the UPF keeps holding. Caller holds
// sc.SMLock (it reads sc.Ref).
func (s *subsystem) untriggerCC(sc *smfctx.SMContext) {
	if s.triggers == nil {
		return
	}

	byNode := s.triggers.takeForSession(sc.Ref)
	if len(byNode) == 0 {
		return
	}

	go s.deactivate(byNode)
}

// deactivate withdraws triggers, grouped by the UPF each was installed at.
//
// Best-effort: the tasks are gone from our bookkeeping either way, so a UPF that
// cannot be reached is left holding a trigger whose session no longer exists. Its
// detection criterion can no longer match any packet, and the keepalive fail-safe
// purges it if we never return.
func (s *subsystem) deactivate(byNode map[string][]types.XID) {
	for nodeID, xids := range byNode {
		endpoint, ok := s.triggers.endpoints[nodeID]
		if !ok {
			continue
		}
		for _, xid := range xids {
			//nolint:errcheck // best-effort withdrawal; a stale trigger that resists is covered by the reconcile fault report
			_ = endpoint.req.DeactivateTask(xid)
		}
	}
}

// forgetDestination drops the belief that this POI still holds our destination, so
// the next trigger re-provisions it. A POI restart is a routine event and takes its
// destination registry with it.
func (e *upfEndpoint) forgetDestination() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.destinationReady = false
}

// ensureDestination provisions this CC-TF's MDF3 destination at the UPF, once.
func (s *subsystem) ensureDestination(endpoint *upfEndpoint) error {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()

	if endpoint.destinationReady {
		return nil
	}

	host, port, err := net.SplitHostPort(s.triggers.mdf3)
	if err != nil {
		return err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return err
	}

	if err := endpoint.req.CreateDestination(x1.Destination{
		DID:          endpoint.did,
		DeliveryType: "X3Only",
		Address:      host,
		Port:         uint16(p),
	}); err != nil {
		return err
	}

	endpoint.destinationReady = true
	return nil
}

// reportTaskIssue tells the LIPF that an authorised interception is not producing
// the content it authorises (TS 33.128 clause 5.2.6). It names the warrant, never
// the target, and never reaches a general log.
func (s *subsystem) reportTaskIssue(warrant types.XID, details string) {
	if s.taskReporter != nil {
		s.taskReporter.NotifyTask(string(warrant), x1.TaskReportTerminatingFault, details)
	}
}

// triggerKey identifies one installed trigger: a warrant, a session, and the UPF
// it was installed at. A session served by several UPFs needs one trigger each.
func triggerKey(warrant types.XID, ref, nodeID string) string {
	return string(warrant) + "|" + ref + "|" + nodeID
}

// plannedTrigger is one trigger this CC-TF has claimed and is about to install.
type plannedTrigger struct {
	endpoint *upfEndpoint
	key      string
	// warrant is the XID of the warrant this trigger serves — what a task issue
	// names, as opposed to trigger.XID, which is this CC-TF's own.
	warrant types.XID
	trigger x1.Trigger
}

// plan claims a trigger XID for every (warrant, session, UPF) triple that does
// not already have one, and returns the triggers to install together with the
// warrants whose serving UPF has no configured triggering endpoint.
//
// Claiming happens here rather than in the install goroutine because the caller
// holds the session lock, and that is what orders it against untriggerCC taking
// the same session's triggers away. Claiming later let a release that ran first
// find nothing to withdraw, after which the install put a trigger at the POI that
// nothing would ever remove — tasking outliving the session it was for, which is
// exactly what must not exist.
//
// A triple that is already claimed is skipped: concurrent establishment and
// mid-session activation can both reach it, and tasking a POI twice for one
// session would have it deliver each packet twice. The detection criterion is the
// session's SEID, which does not change for the life of the PFCP session, so there
// is nothing a ModifyTask would update.
//
// A zero correlation identifier means the anchor's PFCP session does not exist
// yet, so nothing can be planned: a trigger without it is refused by x1.Trigger,
// and reporting that refusal to the LIPF would describe a session that is merely
// still coming up as an interception that has failed. The anchor's establishment
// response brings the CC-TF back here.
func (r *triggerRegistry) plan(
	ref string, tasks []types.InterceptTask, upfs []upfSession, correlation uint64,
) (planned []plannedTrigger, unreachable []types.XID) {
	if correlation == 0 {
		return nil, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, u := range upfs {
		nodeKey, endpoint, ok := r.matchEndpoint(u.node)
		if !ok {
			for _, t := range tasks {
				unreachable = append(unreachable, t.XID)
			}

			continue
		}

		for _, t := range tasks {
			// Keyed by the matched *configured* node, not by whatever it currently
			// resolves to, so withdrawal finds this trigger even if the UPF's address
			// moves while the session is live.
			key := triggerKey(t.XID, ref, nodeKey)
			if _, held := r.installed[key]; held {
				continue
			}

			xid := types.XID(x1.NewUUID())
			r.installed[key] = xid
			planned = append(planned, plannedTrigger{
				endpoint: endpoint,
				key:      key,
				warrant:  t.XID,
				trigger: x1.Trigger{
					XID:           xid,
					ProductID:     t.XID,
					CorrelationID: correlation,
					SEID:          u.seid,
					DIDs:          []string{endpoint.did},
				},
			})
		}
	}

	return planned, unreachable
}

// stillHolds reports whether key is still claimed by xid — false once the session
// has been released or the warrant withdrawn.
func (r *triggerRegistry) stillHolds(key string, xid types.XID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.installed[key] == xid
}

// holds reports whether this process installed the given trigger. The registry is
// keyed by (warrant, session, UPF), so this is a scan — it runs once per
// reconciliation, over a set the size of the live interceptions.
func (r *triggerRegistry) holds(xid types.XID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, installed := range r.installed {
		if installed == xid {
			return true
		}
	}

	return false
}

// release forgets a trigger that could not be installed, so a later attempt
// retries rather than assuming it is in place.
func (r *triggerRegistry) release(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.installed, key)
}

// takeForSession removes every trigger installed for one session, grouped by the
// UPF it was installed at.
func (r *triggerRegistry) takeForSession(ref string) map[string][]types.XID {
	return r.take(func(warrant, session, _ string) bool { return session == ref })
}

// takeForWarrant removes every trigger installed for one warrant, wherever it was
// installed, grouped by UPF. Used when a warrant is deactivated while its sessions
// are still live.
func (r *triggerRegistry) takeForWarrant(warrant types.XID) map[string][]types.XID {
	return r.take(func(w, _, _ string) bool { return w == string(warrant) })
}

// take removes and returns every installed trigger whose key matches, grouped by
// the UPF node it was installed at.
func (r *triggerRegistry) take(match func(warrant, session, nodeID string) bool) map[string][]types.XID {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make(map[string][]types.XID)
	for key, xid := range r.installed {
		warrant, session, nodeID, ok := parseTriggerKey(key)
		if !ok || !match(warrant, session, nodeID) {
			continue
		}
		out[nodeID] = append(out[nodeID], xid)
		delete(r.installed, key)
	}
	return out
}

// parseTriggerKey splits a key back into its warrant, session and UPF parts. A
// node address contains no "|", so splitting into exactly three is unambiguous.
func parseTriggerKey(key string) (warrant, session, nodeID string, ok bool) {
	parts := strings.Split(key, "|")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// untriggerWarrant removes every trigger installed for a warrant, wherever it was
// installed. This is the X1 deactivation path: the warrant is gone, so its
// triggers must go even though the sessions remain. Unlike the FAR state, which is
// re-evaluated against the remaining task set, a trigger belongs to exactly one
// warrant.
func (s *subsystem) untriggerWarrant(warrant types.XID) {
	if s.triggers == nil {
		return
	}

	byNode := s.triggers.takeForWarrant(warrant)
	if len(byNode) == 0 {
		return
	}

	go s.deactivate(byNode)
}
