// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"context"
	"crypto/tls"
	"errors"
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

// upfEndpoint is the CC-TF's client for one UPF, plus the delivery destinations it
// has provisioned there.
type upfEndpoint struct {
	req *x1.Requester
	// node is the configured NodeID, parsed. Held so a session's serving UPF can be
	// matched by identity before anything is resolved (matchEndpoint).
	node smfctx.NodeID

	mu sync.Mutex
	// dids maps an X3 endpoint address to the destination identifier this CC-TF
	// allocated for it and provisioned at this POI. An entry exists only once
	// CreateDestination has succeeded, since a trigger referencing an unprovisioned
	// DID resolves to no destination at the POI (TS 33.128 table 6.2.3-6:
	// destinations are configured "prior to first use").
	//
	// One per address rather than one per UPF, which is what makes a task's own
	// destinations reachable: a warrant names where its content goes, and an element
	// that provisioned a single endpoint could only ever deliver every warrant's
	// content to that one. One per *address* rather than one per task, too — two
	// warrants naming one endpoint share its DID, because the POI deduplicates
	// delivery by address and reports faults by identifier, and a second identifier
	// for one endpoint would report one failure twice.
	dids map[string]string
	// reconciled records that this POI has once told us what it holds. Until it
	// has, this triggering function cannot name that tasking and therefore could
	// never withdraw it — so it owes the POI no liveness signal, and the POI's own
	// fail-safe is left free to act. See keepaliveDue.
	reconciled bool
}

// markReconciled records that this POI has given an authoritative account of its
// tasking. It never goes back to false: what reconciliation establishes is that
// this process, from here on, knows what it installed there.
func (e *upfEndpoint) markReconciled() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reconciled = true
}

func (e *upfEndpoint) isReconciled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.reconciled
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
	// resolved maps a configured node's key to the address it currently resolves to,
	// refreshed on this registry's own goroutine so that matching performs no I/O.
	// An entry is absent only for a name that has never resolved. Guarded by mu.
	resolved map[string]string
	// order is endpoints' keys, sorted, so matching iterates deterministically. Two
	// configured nodes can resolve to one address — transiently, while a Service is
	// being recreated, or permanently in a mistaken configuration — and choosing
	// between them by Go's map order would send a session's triggers to a different
	// UPF from one establishment to the next. The final review found that same
	// nondeterminism in warrant selection at the CC-POI; it is worse here, because
	// the trigger carries the X3 destination.
	order []string

	// reportUnattributable tells the LIPF that a POI's answer could not be bound to
	// the request that produced it. Injected rather than reached through the
	// subsystem because the keepalive goroutine starts inside the constructor,
	// before the subsystem holds the registry — a field assigned afterwards would be
	// written while that goroutine was already reading it.
	reportUnattributable func(error)
	// reportCadenceMissed tells the LIPF that a keepalive round overran the interval it
	// is supposed to keep, so a point of interception may be about to purge live tasking
	// this element is still answering for.
	//
	// It exists because that condition is invisible from the other side: a POI cannot
	// tell a triggering function that has gone away from one that is merely late, and
	// will report the first. nil when no ADMF is configured.
	reportCadenceMissed func(time.Duration)

	// sleep and now are the withdrawal retry loop's clock, held here so a test can
	// drive a backoff measured in minutes without spending it. Nil means the real
	// one — see sleepFor and timeNow, which is what lets a registry be built as a
	// literal.
	sleep func(time.Duration)
	now   func() time.Time
	// lookup resolves a configured node's name, for the same reason: what a name
	// resolves to belongs to the deployment, and a test that had to arrange real DNS
	// to assert on matching would be testing the resolver. Nil means the real one.
	//
	// Guarded by mu, unlike sleep and now, because the goroutine that reads it is
	// this registry's own refresh loop rather than the caller's.
	lookup func(ctx context.Context, host string) (string, error)

	// stop, stopOnce and wg are the registry's lifecycle. Its background work — the
	// address refresh, the keepalive cadence, and the per-warrant propagations it
	// dispatches — is started by Start and ended by Stop, not by the constructor.
	//
	// Two reasons, one in production and one in test. In production, construction
	// happens before the X1 listener is bound and before this subsystem is committed
	// to running; an initialisation that fails after this point must leave nothing
	// behind, and it used to leave a resolver and a keepalive loop running for the
	// life of the process, one set per attempt. In test, a registry built to exercise
	// planning or matching should start no background work at all, and a goroutine
	// outliving its test fails the next one.
	//
	// stop is nil on a registry built as a literal, which several tests do; a nil
	// channel never fires in a select, so those loops are simply not stoppable, and
	// Stop tolerates it rather than closing nil.
	stop     chan struct{}
	stopOnce sync.Once
	// wg counts everything this registry owns — the two loops and each per-warrant
	// propagation runner — so Stop can wait for all of it.
	wg sync.WaitGroup

	// serialMu guards the per-warrant dispatch queues. A separate lock from mu
	// because dispatch happens with the registry already planned and must not be
	// ordered against registry reads.
	serialMu sync.Mutex
	// stopped refuses new dispatch after Stop, which is also what makes wg.Add safe
	// against the wg.Wait inside Stop.
	stopped bool
	// queued and draining are one FIFO queue of outbound propagations per warrant,
	// and whether a runner is currently draining it.
	//
	// **Ordering is the correctness property here, not fairness.** Two ModifyTasks
	// for one warrant dispatched on bare goroutines complete in either order, and both
	// succeed — so a POI can end up labelling content with a delivery identifier the
	// ADMF has already superseded, with both exchanges acknowledged and nothing
	// anywhere recording that the element applied them backwards. Installs need no
	// ordering (plan skips a claimed triple, so two cannot overwrite each other) and
	// withdrawals own their own retry loop keyed by the pending entry; it is the
	// relabel that is last-writer-wins.
	queued   map[types.XID][]func()
	draining map[types.XID]bool

	mu sync.Mutex
	// installed maps a (warrant, session, UPF) triple to the trigger this CC-TF
	// installed for it. The trigger's XID is the CC-TF's own — the warrant's travels
	// in ProductID — and must stay stable from activation to deactivation, so it is
	// remembered rather than recomputed.
	installed map[string]installedTrigger
	// pending holds triggers this CC-TF has decided to withdraw and the POI has not
	// yet acknowledged. Between the two maps the registry answers "what might still
	// be installed", which is the question every other mechanism here actually asks:
	// withdrawn and *believed* withdrawn are not the same state, and treating them
	// as one is what left content interception running with nothing tracking it.
	//
	// Keyed by pendingKey — the trigger key *and* the XID — because the two maps
	// are not in step. A warrant deactivated and re-activated while its POI is
	// unreachable claims the same (warrant, session, UPF) key again, under a new
	// XID, while the old one is still being withdrawn; keying on the trigger key
	// alone would have the second withdrawal displace the first's entry and the
	// first's acknowledgement then clear the second's.
	pending map[string]*pendingWithdrawal
}

// installedTrigger is what this CC-TF put at a POI for one (warrant, session, UPF)
// triple.
//
// It carries the detection criterion and the correlation value as well as the XID,
// because a ModifyTask has to restate them: TS 33.128 table 6.2.3-6 makes both
// mandatory on an LI_T3 trigger, so a modification that changes only how the
// warrant's product is labelled would otherwise have to invent them or tear the
// trigger down and rebuild it — interrupting content the warrant still authorises in
// order to change a label. A registry whose subject is "what might still be
// installed" is the right place to know what it installed.
type installedTrigger struct {
	xid types.XID
	// seid is the PFCP session the trigger detects on, and correlation the value the
	// POI stamps on the content it produces. Both are the session's rather than the
	// warrant's, which is why they are held per trigger and not per task.
	seid        uint64
	correlation uint64
}

// pendingWithdrawal is one trigger whose removal has been attempted and not
// acknowledged. It stays until the POI says the task is gone.
type pendingWithdrawal struct {
	xid    types.XID
	nodeID string
	// since is when the withdrawal was decided, not when it was last attempted:
	// what matters to an operator is how long authority has been withdrawn while
	// content may still be flowing.
	since time.Time
	// failureReported and stuckReported keep each condition to one report. A
	// withdrawal that retries for an hour is one fault, not seven hundred.
	failureReported bool
	stuckReported   bool
}

// withdrawal is one entry of the pending set, handed to the retry loop. Its key is
// the pending one, so an acknowledgement clears exactly what it acknowledged and
// nothing that has since been claimed under the same trigger key.
type withdrawal struct {
	key    string
	nodeID string
	xid    types.XID
}

// pendingKey names one trigger's withdrawal: the trigger key it was installed
// under, and the XID that was installed. Nothing parses it — it need only be
// unique, and the two together are.
func pendingKey(key string, xid types.XID) string { return key + "|" + string(xid) }

// liKeepaliveInterval is how often each triggered POI is told this triggering
// function is still here.
//
// It must be comfortably shorter than the POI's own fail-safe window, since that
// window is what protects against a triggering function that has died: too slow
// and healthy tasking lapses, too fast and it costs a needless request. The POI's
// timeout is its own configuration, so this is deliberately well inside any
// sensible value rather than derived from it.
const liKeepaliveInterval = 60 * time.Second

const (
	// withdrawalRetryInitial is how long the first retry of an unacknowledged
	// withdrawal waits. It doubles up to liKeepaliveInterval and then stays there:
	// a POI is either answering or it is not, and retrying faster than this
	// triggering function's own liveness signal buys nothing.
	withdrawalRetryInitial = 5 * time.Second
	// withdrawalStuckAfter is how long a withdrawal may go unacknowledged before it
	// stops being "the last attempt failed" and becomes "authority was removed some
	// time ago and content is probably still being intercepted". An operator cannot
	// act on a condition that looks the same a second and an hour after it arose.
	withdrawalStuckAfter = 5 * time.Minute
)

// newTriggerRegistry builds the CC-TF's endpoints from configuration. A UPF with
// no configured triggering endpoint cannot be tasked, so CC for a session it
// serves is reported as a fault rather than silently skipped.
func newTriggerRegistry(
	cfg Config,
	clientTLS *tls.Config,
	onUnattributable func(error),
	onCadenceMissed func(time.Duration),
) (*triggerRegistry, error) {
	reg := &triggerRegistry{
		mdf3:                 cfg.MDF3,
		stop:                 make(chan struct{}),
		queued:               make(map[types.XID][]func()),
		draining:             make(map[types.XID]bool),
		endpoints:            make(map[string]*upfEndpoint, len(cfg.UPFTriggers)),
		resolved:             make(map[string]string, len(cfg.UPFTriggers)),
		installed:            make(map[string]installedTrigger),
		pending:              make(map[string]*pendingWithdrawal),
		reportUnattributable: onUnattributable,
		reportCadenceMissed:  onCadenceMissed,
	}
	// The element identifiers already claimed, so two endpoints cannot share one.
	claimedNEIDs := make(map[string]string, len(cfg.UPFTriggers))

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
		// **Two points of interception may not share an element identifier**, and this
		// is the only place the collision is visible: neither UPF can see it, because
		// each is numbering its own product correctly.
		//
		// Every UPF serving one session is deliberately given the *same* delivery
		// identifier and correlation value — that is what joins one warrant's content
		// to its signalling and to the other UPF's content. TS 103 221-2 clause 5.3.9
		// then counts sequence numbers within a context formed from those two plus the
		// network function and interception point identifiers, both of which follow
		// from ne_id. So ne_id is the only thing separating two UPFs' sequence
		// contexts, and two that share it number one context from zero independently.
		//
		// The mediation function receives a single sequence with duplicated numbers and
		// apparent gaps, for a warrant whose product is otherwise entirely correct — and
		// gaps are how loss is made visible on this interface, so the collision forges
		// the signal an agency uses to decide whether it has everything. Under ULCL,
		// where a branching point and a session anchor both serve one session, this is
		// the ordinary multi-UPF case rather than an exotic one.
		if first, dup := claimedNEIDs[t.NEID]; dup {
			return nil, fmt.Errorf(
				"upfTriggers gives %q and %q the same neId %q: two points of interception sharing an "+
					"element identifier number one delivery context independently, which reaches the "+
					"mediation function as duplicated sequence numbers and apparent loss",
				first, t.NodeID, t.NEID)
		}
		claimedNEIDs[t.NEID] = t.NodeID
		reg.endpoints[t.NodeID] = &upfEndpoint{
			node: *smfctx.NewNodeID(t.NodeID),
			req:  x1.NewRequester(t.X1URL, cfg.NEID, t.NEID, clientTLS),
			// Destinations are allocated per X3 endpoint on first use, not one per
			// UPF up front: which endpoints this POI needs is a property of the
			// warrants that arrive, not of the configuration.
			dids: make(map[string]string),
		}
		reg.order = append(reg.order, t.NodeID)
	}
	slices.Sort(reg.order)

	// The address-typed nodes are seeded here, synchronously, because resolving them
	// is not I/O — the value is the answer — and doing it now means the common
	// configuration matches from the first session onward with nothing to wait for.
	//
	// The name-typed ones are left to the loop, which resolves before its first tick.
	// Blocking this constructor on DNS would put a name lookup on the element's
	// startup path, which is the kind of thing this change exists to remove; the cost
	// is that a deployment whose LI block names its UPFs differently from the slice
	// topology has a window of one lookup in which such a session reports a warrant
	// with no triggering endpoint and the next one succeeds. Where the two agree —
	// which is the documented arrangement — matching is by identity and no name is
	// resolved at all.
	reg.seedResolvedLiterals()

	// The loops are NOT started here. See the lifecycle fields: a registry is built
	// before the caller knows whether the subsystem will run at all, and an
	// initialisation that fails after this point has to leave nothing behind. Start
	// is called once the subsystem is committed.

	return reg, nil
}

// Start begins the registry's background work: the address index refresh and the
// keepalive cadence to every triggered point of interception.
//
// Called once, by the initialisation that has decided this subsystem is running.
// Everything it starts is counted in wg, so Stop can prove it has ended.
func (r *triggerRegistry) Start() {
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		r.resolveLoop()
	}()
	go func() {
		defer r.wg.Done()
		r.keepalive()
	}()
}

// Stop ends the registry's background work and waits for it.
//
// It refuses further per-warrant dispatch first — which is also what makes the
// wg.Add in dispatchForWarrant safe against the wg.Wait here — then releases the
// loops and waits for everything in flight. A propagation already running is
// bounded by the X1 requester's own timeout, so this returns.
//
// Idempotent, and safe on a registry whose loops were never started.
func (r *triggerRegistry) Stop() {
	r.serialMu.Lock()
	r.stopped = true
	r.serialMu.Unlock()

	if r.stop != nil {
		r.stopOnce.Do(func() { close(r.stop) })
	}
	r.wg.Wait()
}

// dispatchForWarrant runs job off the caller's goroutine — the caller is the X1
// request goroutine, and these are synchronous HTTPS round trips — and in dispatch
// order against every other job dispatched for the same warrant.
//
// One runner per warrant with work outstanding, so warrants do not serialise
// against each other. See the queued/draining fields for why the ordering is a
// correctness property.
func (r *triggerRegistry) dispatchForWarrant(warrant types.XID, job func()) {
	r.serialMu.Lock()
	if r.stopped {
		// The subsystem is going away. A propagation that cannot be ordered against
		// the ones already queued is worse than one not sent: the POI keeps the label
		// it has, which is a task-level fault the LIPF is told about by the caller.
		r.serialMu.Unlock()

		return
	}
	if r.queued == nil {
		r.queued = make(map[types.XID][]func())
	}
	if r.draining == nil {
		r.draining = make(map[types.XID]bool)
	}
	r.queued[warrant] = append(r.queued[warrant], job)
	if r.draining[warrant] {
		r.serialMu.Unlock()

		return
	}
	r.draining[warrant] = true
	r.wg.Add(1)
	r.serialMu.Unlock()

	go func() {
		defer r.wg.Done()
		r.drainWarrant(warrant)
	}()
}

// drainWarrant runs one warrant's queued propagations in order until none is left.
// A job dispatched while this is running joins the queue rather than starting a
// second runner, which is what keeps the order.
func (r *triggerRegistry) drainWarrant(warrant types.XID) {
	for {
		r.serialMu.Lock()
		queue := r.queued[warrant]
		if len(queue) == 0 {
			delete(r.queued, warrant)
			delete(r.draining, warrant)
			r.serialMu.Unlock()

			return
		}
		job := queue[0]
		r.queued[warrant] = queue[1:]
		r.serialMu.Unlock()

		job()
	}
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
// It performs no I/O. Both sides of the comparison are already resolved by the time
// it runs: the session's address was resolved by sessionUPFs to key the PFCP
// context, and the configured names are resolved on this registry's own goroutine
// (see refreshResolved). That is what took a name lookup off the session lock. The
// caller holds r.mu.
func (r *triggerRegistry) matchEndpoint(session upfSession) (string, *upfEndpoint, bool) {
	for _, key := range r.order {
		if ep := r.endpoints[key]; ep.node.Equal(session.node) {
			return key, ep, true
		}
	}

	// An address this element could not establish never matches, which is the same
	// rule as before by a different route: comparing an unresolved node would make
	// every unresolvable name equal to every other, and task one UPF's CC-POI with
	// another UPF's warrant.
	if session.addr == "" || session.addr == net.IPv4zero.String() {
		return "", nil, false
	}
	for _, key := range r.order {
		if r.resolved[key] == session.addr {
			return key, r.endpoints[key], true
		}
	}

	return "", nil, false
}

// endpointRefreshInterval is how often the configured triggering nodes' names are
// re-resolved. It matches the cadence the SMF's own DNS cache refreshes at, since
// what both are tracking is a Service address that changes when a Service is
// recreated.
const endpointRefreshInterval = 60 * time.Second

// endpointResolveTimeout bounds one name lookup. The value matters less than its
// existence: the lookup this replaces used context.Background() and could block for
// as long as the resolver chose, on a subscriber's signalling path.
const endpointResolveTimeout = 2 * time.Second

// lookupHost resolves a name to one address, or reports that it could not.
//
// It is this package's own rather than the SMF's shared helper, for two reasons that
// happen to point the same way. The shared one logs — "host [X] not found in smf dns
// cache", then "host [X] dns resolved" — which for a name that appears only in LI
// configuration puts an LI-only hostname into the general operator log, and
// undetectability forbids that. And it reads a process-wide map with no
// synchronisation, which is a defect of its own (tracked separately); resolving here
// does not fix that, and does stop LI adding callers to it.
func lookupHost(ctx context.Context, host string) (string, error) {
	var res net.Resolver

	addrs, err := res.LookupHost(ctx, host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("li: %q resolved to no address", host)
	}
	// Normalised through net.IP so the string compares equal to the one sessionUPFs
	// derives from the session's own NodeID, which is that type's String().
	ip := net.ParseIP(addrs[0])
	if ip == nil {
		return "", fmt.Errorf("li: %q resolved to %q, which is not an address", host, addrs[0])
	}

	return ip.String(), nil
}

// refreshResolved re-resolves every configured triggering node and stores the
// answers, so matchEndpoint can compare addresses without performing a lookup.
//
// The lookups happen outside r.mu — they are the slow part, and holding the registry
// lock across them would move the stall from the session lock to the registry's,
// which every other trigger operation waits on.
//
// A name that fails to resolve keeps its previous answer rather than losing it. A
// transient resolver failure is not evidence that a UPF has moved, and dropping the
// entry would stop content interception for every session that UPF serves until the
// resolver recovered. Where there was no previous answer there is nothing to keep,
// and the endpoint simply does not match — which is reported to the LIPF as a
// warrant with no triggering endpoint, and is true.
func (r *triggerRegistry) refreshResolved() {
	// The resolver is read under the lock and used outside it. Reading it under the
	// lock is what makes it safe for a test to substitute one while this loop is
	// already running; using it outside is the point of the whole function, since the
	// lookups are the slow part and holding the registry lock across them would move
	// the stall from the session lock to the registry's.
	r.mu.Lock()
	lookup := r.lookup
	r.mu.Unlock()

	if lookup == nil {
		lookup = lookupHost
	}

	fresh := make(map[string]string, len(r.order))

	for _, key := range r.order {
		node := r.endpoints[key].node
		if node.NodeIdType != smfctx.NodeIdTypeFqdn {
			// An address, not a name: the value *is* the answer. This branch of the
			// shared resolver neither logs nor performs I/O, so it is safe to use.
			fresh[key] = node.ResolveNodeIdToIp().String()

			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), endpointResolveTimeout)
		addr, err := lookup(ctx, string(node.NodeIdValue))
		cancel()

		if err == nil {
			fresh[key] = addr
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for key, addr := range fresh {
		r.resolved[key] = addr
	}
}

// resolveLoop keeps the address index current. Like the keepalive loop it runs for
// the life of the process, because an endpoint's address can change at any point in
// it — a recreated Service is the case this exists for.
func (r *triggerRegistry) resolveLoop() {
	// Before the first tick, not a minute after it: the constructor deliberately does
	// not block on DNS, so this is what closes the window it leaves.
	r.refreshResolved()

	ticker := time.NewTicker(endpointRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.refreshResolved()
		}
	}
}

// seedResolvedLiterals records the address of every configured node that *is* an
// address. No I/O and no logging: for these two node types the shared resolver
// returns the stored value unchanged.
func (r *triggerRegistry) seedResolvedLiterals() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, key := range r.order {
		if node := r.endpoints[key].node; node.NodeIdType != smfctx.NodeIdTypeFqdn {
			r.resolved[key] = node.ResolveNodeIdToIp().String()
		}
	}
}

// keepalive tells each triggered POI this triggering function is still present —
// which is what lets a POI safely purge tasking when it is not. Failures are
// ignored here: a POI that cannot be reached will lapse its own tasking, which is
// the outcome intended, and the trigger path reports the fault when it next tries
// to task it.
func (r *triggerRegistry) keepalive() {
	ticker := time.NewTicker(liKeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.keepaliveRound()
		}
	}
}

// keepaliveRound signals every POI that owes one. Separated from the ticker so the
// behaviour can be driven directly rather than waited for.
//
// **The endpoints are signalled concurrently, and that is a correctness property rather
// than a performance one.** Signalled in line, a round takes as long as the sum of its
// failures: each Keepalive is bounded only by the requester's 10s timeout, on a 60s
// ticker, so around fifteen unreachable UPFs push a round past the POI's own 150s
// fail-safe window. A *healthy* point of interception then goes unsignalled for longer
// than its window allows, purges the tasking it holds, and reports that its triggering
// function went silent — which is true of the interval and false of the cause. An
// operator is sent to investigate a healthy element while the warrant that mattered has
// already stopped producing.
//
// That is the exact fault minTriggerKeepalive exists to prevent, reached by a route the
// floor cannot see: the floor protects the window from the operator's side, and this
// protects the cadence from the sending side. The two are halves of one property, and
// this is the half the element controls. Fanned out, a round costs one peer timeout
// however many endpoints are configured or unreachable.
func (r *triggerRegistry) keepaliveRound() {
	r.mu.Lock()
	due := make(map[string]*upfEndpoint, len(r.endpoints))
	for nodeID, endpoint := range r.endpoints {
		due[nodeID] = endpoint
	}
	r.mu.Unlock()

	var wg sync.WaitGroup

	started := time.Now()

	for nodeID, endpoint := range due {
		if !r.keepaliveDue(nodeID, endpoint) {
			continue
		}

		wg.Add(1)
		go func(endpoint *upfEndpoint) {
			defer wg.Done()

			// Best-effort: a missed keepalive is transient, and a POI that has really
			// gone away trips its own fail-safe; nothing here to act on per tick.
			//
			// A response that could not be *bound* to the request is a different fault
			// and is not best-effort. A keepalive answered by an endpoint naming another
			// element means this triggering function believes a POI is alive on the
			// strength of an answer from something else — the same silent condition the
			// tasking paths report, on the one exchange whose whole purpose is to say the
			// peer is still there. reportUnattributable filters for exactly that and
			// ignores every transient failure, so handing it the error keeps the
			// best-effort behaviour this loop was written for.
			if err := endpoint.req.Keepalive(); err != nil && r.reportUnattributable != nil {
				r.reportUnattributable(err)
			}
		}(endpoint)
	}

	wg.Wait()

	// And where the cadence still cannot be kept, say so rather than leaving it to be
	// inferred from a purge at the other end. From the POI's side an overrun is
	// indistinguishable from a triggering function that has gone away — it will purge
	// and report exactly that — so the element that can tell the difference is this one.
	if elapsed := time.Since(started); elapsed > liKeepaliveInterval && r.reportCadenceMissed != nil {
		r.reportCadenceMissed(elapsed)
	}
}

// keepaliveDue reports whether this triggering function owes a POI the signal that
// it is still here. It owes it for tasking it can name, and for nothing else.
//
// Keeping every *configured* endpoint alive disables the POI's fail-safe by
// construction: the fail-safe is the last mechanism able to reclaim tasking a
// triggering function has forgotten, and a POI holding a forgotten trigger was
// being told, once a minute, that the function responsible for it was alive and
// well. So an endpoint this process holds nothing at falls silent and the POI
// reclaims whatever it still holds; an endpoint that has not yet answered what it
// holds falls silent too, because after a restart this process cannot name that
// tasking and so could never withdraw it.
//
// Both directions fail toward interception stopping, which is the direction a
// fail-safe must fail in. What this cannot do is reclaim one orphan at an endpoint
// that also holds live tasking: the fail-safe is per-connection, so the live task's
// keepalives preserve the orphan with it. Durable withdrawal is the remedy for
// that; this only makes the backstop reachable at all.
func (r *triggerRegistry) keepaliveDue(nodeID string, e *upfEndpoint) bool {
	return e.isReconciled() && r.tasksAt(nodeID)
}

// tasksAt reports whether this triggering function believes the POI at nodeID
// holds anything it installed. Pending counts: a withdrawal in flight is tasking
// this function is still answerable for, and going silent under it would ask the
// POI's fail-safe to finish a job this process has not given up on.
func (r *triggerRegistry) tasksAt(nodeID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for key := range r.installed {
		if _, _, node, ok := parseTriggerKey(key); ok && node == nodeID {
			return true
		}
	}
	for _, p := range r.pending {
		if p.nodeID == nodeID {
			return true
		}
	}

	return false
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
// Started at startup, one goroutine per POI: it is network I/O, nothing else waits
// on it, and a POI that is slow or down must not hold up reconciliation of the
// others — theirs is what lets them be kept alive again.
func (s *subsystem) reconcileTriggers() {
	if s.triggers == nil {
		return
	}

	for _, nodeID := range s.triggers.order {
		go s.reconcileEndpoint(nodeID, s.triggers.endpoints[nodeID])
	}
}

// reconcileEndpoint establishes what one POI holds and withdraws what no live
// warrant corresponds to, retrying until it has an authoritative answer.
//
// One attempt is not reconciliation. A POI unreachable at startup and reachable a
// minute later — the ordinary shape of a whole-cluster restart — was abandoned
// with a fault report and never revisited, while this process resumed keepalives
// to it regardless: the POI was then kept alive, for the life of the process, by a
// triggering function that could not name a single thing it held. Retrying is what
// makes that state temporary, and the keepalive gating (keepaliveDue) is what makes
// it safe while it lasts.
func (s *subsystem) reconcileEndpoint(nodeID string, endpoint *upfEndpoint) {
	var reported []x1.TaskResponseDetails
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			s.triggers.sleepFor(withdrawalBackoff(attempt - 1))
		}

		var err error
		reported, err = endpoint.req.ReportedTasks()
		if err == nil {
			break
		}
		// The POI may simply not be up yet — on a whole-cluster restart it very
		// likely is not. Worth telling the LIPF, because tasking may have been left
		// behind that this process cannot withdraw until this succeeds. Reported as
		// an element-level issue, not a task one: a task report has to name an XID,
		// and which warrants they were is precisely what was lost. Once, not per
		// attempt — the retry is this element's business, the condition is the LIPF's.
		if attempt == 0 && s.reporter != nil {
			s.reporter.Notify(x1.NEIssueReconcileFailed,
				"could not establish what content tasking a UPF still holds after restart; retrying")
		}
	}

	// From here this process knows what this POI holds, so it may resume telling it
	// that it is here. Before this point its silence is what lets the POI's own
	// fail-safe reclaim tasking nobody can name.
	endpoint.markReconciled()

	var orphans []withdrawal
	for _, task := range reported {
		xid := types.XID(task.TaskDetails.XID)
		if xid == "" {
			continue
		}

		// Skip anything this process is answerable for. Reconciliation runs
		// concurrently with ordinary triggering, so a session establishing right
		// now would otherwise have its brand-new trigger withdrawn by the cleanup —
		// and one being withdrawn right now would be withdrawn twice, by two
		// parties neither of which can read the other's answer.
		if held, withdrawing := s.triggers.holds(xid); held {
			// It is ours, so it is not stale — but the POI's account of it is the
			// only way this function learns that a trigger it installed is not
			// actually running. A failed provisioning or an unresolved fault means
			// content interception has stopped while the warrant is live, which is
			// precisely what a CC triggering function exists to notice. The reply
			// was previously read for XIDs and nothing else. A trigger already on
			// its way out is exempt: it is meant to stop.
			if !withdrawing && !task.TaskStatus.Healthy() && s.reporter != nil {
				s.reporter.Notify(x1.NEIssueTriggerFaulty,
					"a UPF reports a content trigger this SMF installed as not running: "+
						task.TaskStatus.Describe())
			}

			continue
		}

		// Nothing here knows about this one, which after a restart means all of it.
		// Withdrawing is the only way it ever stops — and it goes through the same
		// pending-removal state as any other withdrawal, because a withdrawal
		// reconciliation fires and forgets leaves exactly the tasking reconciliation
		// exists to remove.
		orphans = append(orphans, s.triggers.takeOrphan(nodeID, xid))
	}

	// Synchronously, on this endpoint's own goroutine: a POI that will not
	// acknowledge holds up nothing but its own reconciliation.
	s.deactivate(orphans)
}

// upfSession is one UPF serving a session, with the detection criterion for that
// UPF's share of it.
type upfSession struct {
	// node is the serving UPF's N4 NodeID as the session carries it, passed on
	// unresolved so matchEndpoint can compare identities before addresses.
	node smfctx.NodeID
	// addr is that node's address, as sessionUPFs has *already* resolved it to key
	// the session's PFCP context. Carried rather than re-derived, because deriving
	// it again is a name lookup — and matchEndpoint ran on the PDU-session
	// establishment path of the subscriber being intercepted, holding that session's
	// lock and the registry's, with no timeout on the lookup. Every other exchange
	// on this path is deliberately off-goroutine for exactly that reason; this one
	// was not, and a name lookup is network I/O however small its answer.
	addr string
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
			// key is that address, already resolved for the PFCP context lookup above.
			// Passing it on is what keeps matchEndpoint from resolving the same name a
			// second time, on this goroutine, under this session's lock.
			out = append(out, upfSession{node: node.UPF.NodeID, addr: key, seid: pfcpCtx.RemoteSEID})
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

// POIRestarted tells the CC Triggering Function that a triggered point of interception
// has restarted, so the tasking this element believes it holds there is discarded and
// subsequent establishments and scans re-install it. Silent no-op unless LI is configured.
//
// **It takes the node identity and its address, not a pre-resolved string**, because the
// registry has to be allowed to apply its own matching rule. Trigger keys carry
// `li.upfTriggers[].nodeId` exactly as configured — which the chart and the blueprint default
// to `upf`, a name — while every caller here holds a `smfctx.NodeID` whose resolved form is
// an address. Handed the address, ForgetPOI's string equality matched nothing and this
// notification did nothing at all: the registry kept every claim for the restarted POI, so
// `plan` found each triple already claimed and installed nothing, while the POI held no
// tasking and discarded the copies it was told to make. The only existing test passed
// because it configured an IP literal, the one spelling in which the two forms coincide.
//
// So the two values travel in the shape sessionUPFs already builds, and matchEndpoint
// resolves them to a configured key — identity first, then the refreshed address index —
// which is the same rule the trigger path uses. ForgetPOI stays as the key-level primitive.
//
// **What this does not do is restore the subscriber's sessions.** Those are lost on the same
// path, which is the pre-existing upstream `// TODO: Session cleanup required` beside each
// caller and a larger problem than this one. What is in scope is that the interception
// bookkeeping stops being the reason re-tasking cannot happen once that TODO is addressed.
func POIRestarted(node smfctx.NodeID, addr string) {
	sub := active.Load()
	if sub == nil || sub.triggers == nil {
		return
	}
	if n := sub.triggers.forgetRestartedPOI(upfSession{node: node, addr: addr}); n > 0 && sub.reporter != nil {
		// NE-level and countable, naming no warrant: which interceptions were lost is
		// the ADMF's to work out from its own provisioning, and this element cannot
		// name them without disclosing tasking on a channel that must not carry it.
		sub.reporter.NotifyAsync(x1.NEIssueReconcileFailed,
			"a triggered point of interception restarted; the tasking this element believed it held "+
				"there has been discarded and will be re-installed as sessions are established or scanned")
	}
}

// UntriggerCC removes the LI_T3 triggers installed for sc. Call it when the
// session is released (TS 33.128 clause 6.2.3.3.1). Caller holds sc.SMLock.
func UntriggerCC(sc *smfctx.SMContext) {
	if sub := active.Load(); sub != nil && sc != nil {
		sub.untriggerCC(sc)
	}
}

// RestoreInterception makes a session's release reportable again, for a release that
// did not happen. Caller holds sc.SMLock.
//
// The SMF reports the release and withdraws the session's triggers *before* PFCP
// deletion, and that order is right rather than wrong: stopping interception before or
// as the session goes is the fail-closed direction, and withdrawal needs the
// serving-UPF list that hangs off sc.Tunnel. What was missing is that nothing put the
// *report* state back on the branches where the deletion times out or fails and the
// session is restored to service — so the release that eventually happened was
// suppressed as a duplicate of one that never occurred, and the agency's record of the
// session ended at a failed attempt, permanently. That is what this restores, and it is
// the half the spec obliges: `A record reports the transition it names` requires the
// eventual release to stay reportable.
//
// **It does not re-install the triggers, and it cannot.** An earlier version called
// triggerCC from here and its comment said the interception was restored. Every
// reachable caller runs after releaseTunnel has set sc.Tunnel = nil
// (producer/pdu_session.go), and a session with no tunnel has no serving UPFs, so
// sessionUPFs returns nothing and triggerCC returns before planning anything. The call
// was unreachable on every branch while the comment asserted it had run.
//
// Snapshotting the UPF list before releaseTunnel and re-triggering afterwards is not
// the fix. It would install a trigger keyed to a PFCP session that has been deleted,
// into a session that cannot forward — a trigger matching no packet, held by a
// triggering function that believes interception is running. That is the state this
// whole capability exists to prevent, arrived at by trying to prevent it.
//
// So the durable withdrawal stands: this element has withdrawn the triggers, the POI
// has acknowledged, and content interception for this session is over until something
// re-establishes it. What would re-establish it is the session's own user-plane state
// coming back, which is the pre-existing upstream `// TODO: Session cleanup required`
// (pfcp/handler/handler.go, pfcp/adapter/adapter.go) and a larger problem than this
// one — the same entanglement ForgetPOI records. **Do not re-raise the re-install
// here**: it is absent because it cannot work from a session with no tunnel, not
// because it was overlooked.
func RestoreInterception(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	sc.LiReleaseReported = false
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
	planned, unreachable, undeliverable := s.triggers.plan(sc.Ref, tasks, upfs, servingUPFSEID(sc))

	if len(planned) == 0 && len(unreachable) == 0 && len(undeliverable) == 0 {
		return
	}

	// Everything that talks to a peer goes off this goroutine, the reports included.
	//
	// This runs on HandlePfcpSessionEstablishmentResponse's path with sc.SMLock held,
	// for the very subscriber being intercepted. ReportTaskIssue is a synchronous mTLS
	// POST bounded only by its own 10s timeout, and — unlike an NE-level report — it is
	// deliberately *not* throttled, because each task's failure is its own fact. So
	// every affected warrant used to cost the establishment a full timeout while an
	// ADMF was unreachable, under the session's own lock: a tasked subscriber's session
	// setup measurably slower than an untasked one's, which is the target-observable
	// timing difference this element must never produce.
	go func() {
		// A UPF we have no triggering endpoint for is carrying a tasked session's
		// traffic and cannot be told whose warrant it serves. The interception is
		// authorised and will produce nothing, which only the LIPF can resolve.
		for _, warrant := range unreachable {
			s.reportTaskIssue(warrant, "no triggering endpoint configured for a UPF serving the target")
		}

		// And a warrant whose content has nowhere to go at all: it named no X3
		// destination this element can resolve and there is no configured endpoint to
		// fall back to. Reported separately from the above because the remedy is a
		// different one — provision the destination, or configure the fallback.
		for _, warrant := range undeliverable {
			s.reportTaskIssue(warrant, "no X3 delivery destination could be resolved for this task")
		}

		s.installTriggers(planned)
	}()
}

// installTriggers performs the X1 exchanges off the signalling path. Every
// trigger it is given has already been claimed in the registry by triggerCC, so
// the withdrawal path can see it even before it exists at the POI.
func (s *subsystem) installTriggers(planned []plannedTrigger) {
	for _, p := range planned {
		dids, err := s.ensureDestinations(p.endpoint, p.addresses)
		if err != nil {
			// Released rather than withdrawn, and the asymmetry with the activation
			// below is the point: no ActivateTask has been sent, so whatever happened
			// to the CreateDestination, this POI holds no trigger of ours. There is
			// nothing to withdraw.
			s.triggers.release(p.key)
			s.reportTaskIssue(p.warrant, "X3 delivery destination could not be provisioned at the UPF")
			// The first X1 exchange of the sequence, so an answer this element
			// cannot bind surfaces here before it ever reaches the activation.
			s.reportUnattributable(err)

			continue
		}
		p.trigger.DIDs = dids

		err = p.endpoint.req.ActivateTask(p.trigger)
		if err != nil {
			// A refusal may mean the POI has lost the destinations we provisioned —
			// it restarts independently of us, and its destination registry does not
			// survive that. Re-provision and try once more before concluding the
			// interception cannot be arranged: the alternative is content dropped
			// at the POI for as long as this process happens to live.
			p.endpoint.forgetDestination()

			if again, retryErr := s.ensureDestinations(p.endpoint, p.addresses); retryErr == nil {
				p.trigger.DIDs = again
				err = p.endpoint.req.ActivateTask(p.trigger)
			}
		}

		if err != nil {
			// What happens to the bookkeeping turns on whether the POI *said* it
			// holds nothing, or said nothing at all.
			//
			// A stated refusal is a negative answer: the POI received the request,
			// understood it, and declined. Nothing is installed, so the claim is
			// dropped and a later establishment or modification retries.
			//
			// Anything else — a timeout, a lost response, an answer this element
			// cannot bind to its request — is not an answer. The POI may well hold
			// the trigger. Dropping the claim then leaves it installed and untracked:
			// absent from both maps, so a warrant's withdrawal finds nothing, a
			// session's release finds nothing, and reconciliation runs only at
			// startup. The POI goes on duplicating the subject's content, correctly
			// labelled and indistinguishable downstream, past the point where the
			// warrant is revoked. So it is withdrawn instead, durably, and the POI's
			// own "XID not held" answer completes that withdrawal at once in the case
			// where it never received the activation at all.
			var refused *x1.RequestError
			if errors.As(err, &refused) {
				s.triggers.release(p.key)
			} else if w, owned := s.triggers.takeFailedActivation(p.key, p.trigger.XID); owned {
				// On its own goroutine: the retry loop runs until the POI
				// acknowledges, and the triggers behind this one in the batch must
				// not wait for it.
				go s.deactivate([]withdrawal{w})
			}

			// Either way the LIPF is told this warrant is producing no content.
			s.reportTaskIssue(p.warrant, "the UPF refused or failed the content-interception trigger")
			// And, where the cause was an answer this element could not bind to its
			// request, say so separately. The task issue above is the same whether
			// the POI refused the warrant or this element disbelieved its answer,
			// and those need opposite actions — the first is a POI to look at, the
			// second a configuration mismatch here.
			s.reportUnattributable(err)

			continue
		}

		// The session may have been released, or the warrant withdrawn, in the time
		// this trigger took to install. That withdrawal ran against a registry entry
		// whose trigger did not yet exist at the POI, so whatever it sent was refused
		// and the trigger is now in place with nothing tracking it: reconciliation
		// runs only at startup, and the POI's fail-safe only fires once this SMF
		// stops answering it, so nothing would ever take it down. Withdraw it here.
		if !s.triggers.stillHolds(p.key, p.trigger.XID) {
			// **Durably, not best-effort.** This was one DeactivateTask whose failure
			// left the trigger installed and untracked, on the reasoning that the POI's
			// fail-safe is the last resort — and the requirement beside this one records
			// why that fail-safe cannot help here: the element's *other* tasking at this
			// POI keeps the keepalive relationship alive, so the POI never concludes its
			// triggering function has gone and never purges. The single attempt was
			// relying on a mechanism this project has documented as unable to reclaim
			// exactly this orphan.
			//
			// So it goes into the same pending-removal state every other withdrawal
			// uses, and the retrying deactivate path owns it until the POI says the task
			// is gone. takeOrphan is the shape: this trigger's claim is no longer in the
			// registry under its key — that is what stillHolds just reported — so the
			// pending entry gets a synthetic key, as reconciliation's orphans do.
			//
			// Exactly one party withdraws, as before: stillHolds reports true while a
			// withdrawal of this XID is pending, so a session release that raced this
			// activation is already owned by its own retry loop and this branch does not
			// run. What reaches here is the trigger that is in neither map — released
			// without a withdrawal, or displaced by a newer claim under the same key —
			// which is precisely the orphan nothing else can name.
			_, _, nodeID, ok := parseTriggerKey(p.key)
			if !ok {
				// Unaddressable, so no withdrawal can be sent anywhere. Every key this
				// element builds parses; reported rather than looped on forever.
				s.reportTaskIssue(p.warrant,
					"a content trigger installed after its own withdrawal cannot be addressed for removal")

				continue
			}
			// On its own goroutine: the retry loop runs until the POI acknowledges, and
			// the triggers behind this one in the batch must not wait for it.
			go s.deactivate([]withdrawal{s.triggers.takeOrphan(nodeID, p.trigger.XID)})
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

	pending := s.triggers.takeForSession(sc.Ref)
	if len(pending) == 0 {
		return
	}

	go s.deactivate(pending)
}

// deactivate withdraws pending triggers at the UPF each was installed at, and
// keeps trying until every one of them is acknowledged.
//
// Its two callers arrive with opposite premises, and this function used to hold
// only the first one's. untriggerCC releases a session that is *gone*: the
// trigger's detection criterion is that session's SEID, so it can no longer match
// a packet and a POI that keeps the trigger produces nothing from it.
// untriggerWarrant withdraws *authority* from sessions that remain: the criterion
// still matches every packet the subject sends, so a POI that keeps that trigger
// keeps delivering the subject's content to the MDF under a warrant that no longer
// exists — well-formed, correctly attributed, and unauthorised. Nothing downstream
// can tell, which is why best-effort is not available here and the entry stays in
// the registry until the POI says the task is gone.
//
// Runs on its own goroutine (both callers start it with go): the retry loop
// outlives the X1 request that began it, by design.
func (s *subsystem) deactivate(pending []withdrawal) {
	for attempt := 0; len(pending) > 0; attempt++ {
		if attempt > 0 {
			s.triggers.sleepFor(withdrawalBackoff(attempt - 1))
		}

		var remaining []withdrawal
		for _, w := range pending {
			endpoint, ok := s.triggers.endpoints[w.nodeID]
			if !ok {
				// The endpoint is keyed by the NodeID as configured and configuration is
				// read once, so this cannot happen for a trigger this process installed.
				// If it ever does, no request can be addressed anywhere, and retrying an
				// unaddressable withdrawal forever would be a loop with no exit.
				s.triggers.forgetPending(w.key)

				continue
			}

			if err := endpoint.req.DeactivateTask(w.xid); err != nil && !withdrawalComplete(err) {
				remaining = append(remaining, w)
				s.reportWithdrawalFailure(w.key, err)

				continue
			}
			s.triggers.forgetPending(w.key)
		}
		pending = remaining
	}
}

// x1CodeNoSuchTask is TS 103 221-1 table 6.7-3 code 2020, "XID does not exist on
// NE". Named here rather than imported because x1 keeps its copy unexported for
// the server side; the two must stay in step.
const x1CodeNoSuchTask = 2020

// withdrawalComplete reports whether an error from DeactivateTask means the
// tasking is already gone — which is what the withdrawal was for.
//
// Only 2020 qualifies, and only here. The POI is required to answer it for an XID
// it does not hold, and the situations that produce it are the ordinary ones: the
// POI restarted, or its keepalive fail-safe purged tasking this element could no
// longer name. Read as a failure, it makes the retry loop run hardest exactly
// when the withdrawal has most certainly succeeded, and the loop has no exit —
// the POI's answer cannot change.
//
// What that costs is both of the things the pending state exists to protect.
// taskingWithdrawalStuck says content is probably still being intercepted without
// authority; raised over tasking the POI has confirmed absent, it sends an
// operator after an interception that is not running, and an alarm that cries
// wolf is not one anybody acts on when it is real. Meanwhile the entry that can
// never clear keeps keepaliveDue true, and those keepalives are precisely what
// stops that POI's fail-safe from reclaiming any orphaned tasking it does hold.
// So the misreading manufactures the alarm for unauthorised interception and
// disables the mechanism that would end a real case of it, at once.
//
// The classification stays on this side rather than moving into the x1 client
// because 2020 only means "already done" for a withdrawal. Answering the same
// code to an activation means what it says, and folding it into the transport
// would make tasking against a vanished task look like it worked.
func withdrawalComplete(err error) bool {
	var reqErr *x1.RequestError

	return errors.As(err, &reqErr) && reqErr.Code == x1CodeNoSuchTask
}

// reportWithdrawalFailure tells the LIPF that a withdrawal did not land, and
// separately that one has now been outstanding long enough to mean something
// worse. Both are element-level conditions: they name no XID, because what an
// operator must know is that this element cannot end an interception it has been
// told to end, and a channel carrying that must not also carry whose it was.
//
// It also says *which side* the failure is on, and that is not cosmetic. A
// withdrawal whose answer this element refuses is not a POI problem: the POI may
// be answering perfectly well and being disbelieved, because the identity it
// states is not the one this SMF addressed, or its version is one this element
// does not speak. Reported only as taskingWithdrawalFailed, that presents as a POI
// at fault and sends an operator to look in the wrong place — and it is precisely
// the failure that does not resolve itself, because the pending entry never
// clears, the retries never stop, and the keepalives a pending entry earns keep
// the POI's own fail-safe from reclaiming the tasking either. Both remedies are
// held open by the same condition, so naming it is what makes it actionable.
func (s *subsystem) reportWithdrawalFailure(key string, cause error) {
	first, stuck := s.triggers.noteFailure(key)
	if s.reporter == nil {
		return
	}

	s.reportUnattributable(cause)

	if first {
		s.reporter.Notify(x1.NEIssueTaskingWithdrawalFailed,
			"a UPF did not acknowledge the withdrawal of a content trigger; retrying")
	}
	if stuck {
		s.reporter.Notify(x1.NEIssueTaskingWithdrawalStuck,
			"a content trigger has been unacknowledged since its withdrawal was ordered, "+
				"long enough that content interception is probably continuing without authority")
	}
}

// forgetDestination drops the belief that this POI still holds our destinations, so
// the next trigger re-provisions them. A POI restart is a routine event and takes its
// whole destination registry with it, so all of them go and not just the one whose
// trigger happened to fail.
func (e *upfEndpoint) forgetDestination() {
	e.mu.Lock()
	defer e.mu.Unlock()
	clear(e.dids)
}

// ensureDestinations provisions the X3 endpoints a task names at this UPF, and
// returns the destination identifiers to put on its trigger.
//
// Provisioned once per address per POI, and the DID is remembered: two warrants
// naming one endpoint share it. The POI deduplicates delivery by address, so a
// second identifier for the same endpoint would buy nothing and would split that
// endpoint's fault reporting across two identifiers the ADMF would have to
// reassemble.
//
// A DID is recorded only once CreateDestination has succeeded. Recording it first
// would leave the trigger naming a destination the POI does not hold, which
// RequireResolvableDIDs at the POI refuses — correctly, and pointlessly, since this
// element could have known.
func (s *subsystem) ensureDestinations(endpoint *upfEndpoint, addresses []string) ([]string, error) {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()

	dids := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		did, held := endpoint.dids[addr]
		if held {
			dids = append(dids, did)

			continue
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, err
		}

		did = x1.NewUUID()
		if err := endpoint.req.CreateDestination(x1.Destination{
			DID:          did,
			DeliveryType: "X3Only",
			Address:      host,
			Port:         uint16(p),
		}); err != nil {
			return nil, err
		}

		endpoint.dids[addr] = did
		dids = append(dids, did)
	}

	return dids, nil
}

// reportUnattributable tells the LIPF that this element received an X1 answer it
// could not bind to the request that produced it, naming the envelope field that
// disagreed and nothing else.
//
// It is called beside a task-level report rather than instead of one: on this path
// the element does know which warrant it was installing, so the task issue is
// true and useful. What it cannot convey is *which side* the fault is on, and that
// is what this adds. A response that cannot be attributed is an element-level
// condition however much context the caller happens to hold.
func (s *subsystem) reportUnattributable(cause error) {
	var unattributable *x1.ResponseError
	if s.reporter == nil || !errors.As(cause, &unattributable) {
		return
	}
	s.reporter.Notify(x1.NEIssueX1ResponseUnattributable,
		"a POI's answer could not be bound to the request that produced it ("+
			unattributable.Field+"); the POI may be answering correctly and being refused here")
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
	// addresses are the X3 endpoints this warrant's content goes to. They are
	// carried rather than the DIDs because turning one into the other means
	// provisioning it at the POI, which is a network exchange and belongs on the
	// install goroutine — plan runs under the session lock. trigger.DIDs is filled
	// in there.
	addresses []string
	trigger   x1.Trigger
}

// x3Destinations is where this task's content goes.
//
// The task's own destinations first, which is what TS 33.128 requires and what the
// IRI path already does (see x2Destinations, which this mirrors deliberately —
// the two answer the same question for the two interfaces and had no business
// answering it differently).
//
// **The configured MDF3 serves a task that named no destination, not one whose
// destinations produced no X3 endpoint.** The two were the same test — an empty resolved
// list — and they are different facts: a task that named nothing is a gap the
// provisioning function left, and one that named an X2-only destination is an assertion
// this element cannot honour by substituting an endpoint of its own. On an element
// serving several agencies the substitution sends a warrant's content to whichever
// address local configuration happens to name.
//
// Until the task's own destinations were consulted at all, the configured endpoint served
// *every* task, so two agencies' content arrived at whichever address configuration
// happened to name. This is the last of that defect, and it is the same one the IRI path
// had.
func (r *triggerRegistry) x3Destinations(t types.InterceptTask) []string {
	if addrs := t.DeliveryAddresses(types.DeliveryX3); len(addrs) > 0 {
		return addrs
	}
	if len(t.DIDs) > 0 {
		return nil
	}
	if r.mdf3 == "" {
		return nil
	}

	return []string{r.mdf3}
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
//
// undeliverable carries the warrants whose content has nowhere to go — the task
// names no X3 destination this element can resolve and no MDF3 is configured to
// fall back to. It is reported separately from unreachable because the two are
// different faults with different remedies: one is a UPF this element cannot task,
// the other a destination it cannot find.
func (r *triggerRegistry) plan(
	ref string, tasks []types.InterceptTask, upfs []upfSession, correlation uint64,
) (planned []plannedTrigger, unreachable, undeliverable []types.XID) {
	if correlation == 0 {
		return nil, nil, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// A warrant is reported unreachable once, however many of the session's UPFs this
	// element has no endpoint for. The fault is about the warrant — it is authorised
	// and some of its content cannot be attributed — and it is one fault whether one
	// UPF or three are missing an entry; a per-UPF report multiplied one condition into
	// as many unthrottled POSTs as the session had unmatched endpoints (two UPFs and
	// three warrants produced six), all of them naming the same remedy at the LIPF.
	reportedUnreachable := make(map[types.XID]bool, len(tasks))

	for _, u := range upfs {
		nodeKey, endpoint, ok := r.matchEndpoint(u)
		if !ok {
			for _, t := range tasks {
				if reportedUnreachable[t.XID] {
					continue
				}
				reportedUnreachable[t.XID] = true
				unreachable = append(unreachable, t.XID)
			}

			continue
		}

		for _, t := range tasks {
			// Where this warrant's content goes. Resolved per task rather than per
			// element: the destinations are the task's, and an element substituting its
			// own is how two agencies' content came to arrive at one endpoint.
			addresses := r.x3Destinations(t)
			if len(addresses) == 0 {
				undeliverable = append(undeliverable, t.XID)

				continue
			}

			// Keyed by the matched *configured* node, not by whatever it currently
			// resolves to, so withdrawal finds this trigger even if the UPF's address
			// moves while the session is live.
			key := triggerKey(t.XID, ref, nodeKey)
			if _, held := r.installed[key]; held {
				continue
			}

			xid := types.XID(x1.NewUUID())
			r.installed[key] = installedTrigger{xid: xid, seid: u.seid, correlation: correlation}
			planned = append(planned, plannedTrigger{
				endpoint:  endpoint,
				key:       key,
				warrant:   t.XID,
				addresses: addresses,
				trigger: x1.Trigger{
					XID: xid,
					// The label the POI will put on its xCC, and it must be the one this
					// element puts on its own xIRI for the same warrant — the ADMF's
					// productID where it provisioned one, per TS 103 221-1 clause 6.2.1.2.
					// The task XID is the wrong value whenever the two differ: an MDF
					// attributes on this field alone, so signalling labelled one way and
					// content the other are two unrelated intercepts to it, with nothing
					// in either stream to show they were meant to join. Both sides stay
					// well-formed and separately deliverable, which is why nothing reports
					// it. Above, t.XID is correct — the registry keys tasking by the
					// warrant this element was tasked with, not by how product is labelled.
					ProductID:     t.DeliveryXID(),
					CorrelationID: correlation,
					SEID:          u.seid,
					// DIDs are filled by installTriggers, once the addresses above
					// have been provisioned at this POI. Provisioning is a network
					// exchange and this runs under the session lock.
				},
			})
		}
	}

	return planned, unreachable, undeliverable
}

// stillHolds reports whether this registry is still answerable for the trigger
// claimed under key — either because it is installed, or because a withdrawal of
// it is pending. False means nobody is tracking it, and the caller must take it
// down itself.
//
// A pending entry counts as held on purpose: the retry loop already owns that
// trigger, and a second party withdrawing the same XID concurrently is two
// requests where the POI's answer to one is indistinguishable from its answer to
// the other.
func (r *triggerRegistry) stillHolds(key string, xid types.XID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.installed[key].xid == xid {
		return true
	}
	_, pending := r.pending[pendingKey(key, xid)]

	return pending
}

// holds reports whether this process is answerable for the given trigger, and
// whether it is on its way out. The registry is keyed by (warrant, session, UPF),
// so this is a scan — it runs once per reconciliation, over a set the size of the
// live interceptions.
//
// withdrawing separates "ours and running" from "ours and being withdrawn":
// reconciliation must leave both alone, but only the first is a trigger whose
// health at the POI is worth reporting.
func (r *triggerRegistry) holds(xid types.XID) (held, withdrawing bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, installed := range r.installed {
		if installed.xid == xid {
			return true, false
		}
	}
	for _, p := range r.pending {
		if p.xid == xid {
			return true, true
		}
	}

	return false, false
}

// release forgets a trigger that could not be installed, so a later attempt
// retries rather than assuming it is in place.
func (r *triggerRegistry) release(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.installed, key)
}

// takeForSession moves every trigger installed for one session into the
// pending-removal state, ready to be withdrawn.
func (r *triggerRegistry) takeForSession(ref string) []withdrawal {
	return r.take(func(warrant, session, _ string) bool { return session == ref })
}

// takeForWarrant moves every trigger installed for one warrant, wherever it was
// installed, into the pending-removal state. Used when a warrant is deactivated
// while its sessions are still live.
func (r *triggerRegistry) takeForWarrant(warrant types.XID) []withdrawal {
	return r.takeForWarrantExcept(warrant, nil)
}

// takeForWarrantExcept is takeForWarrant for a warrant whose task has been
// modified rather than removed: the triggers for sessions in keep stay installed,
// because the modified task still covers them and their interception is not
// meant to be interrupted.
func (r *triggerRegistry) takeForWarrantExcept(warrant types.XID, keep map[string]bool) []withdrawal {
	return r.take(func(w, session, _ string) bool {
		return w == string(warrant) && !keep[session]
	})
}

// forgetRestartedPOI discards the claims held for the POI serving one node, matched the way
// every other trigger path matches it.
//
// It exists because the caller knows a node and its address and the registry is keyed by a
// configured string, and only the registry can turn one into the other. Doing it here rather
// than at the call site is also what keeps the *one* matching rule in one place: an
// unresolvable node never matches, which is right — a claim discarded for the wrong POI would
// re-install one element's tasking at another's, which is the defect matchEndpoint's own
// documentation exists to prevent.
//
// The lock is taken twice deliberately. matchEndpoint documents needing r.mu and ForgetPOI
// takes it itself; nothing between the two can invalidate the key, because endpoints and
// order are written once at construction.
func (r *triggerRegistry) forgetRestartedPOI(session upfSession) int {
	r.mu.Lock()
	key, _, ok := r.matchEndpoint(session)
	r.mu.Unlock()

	if !ok {
		return 0
	}

	return r.ForgetPOI(key)
}

// ForgetPOI discards this element's record of what a triggered point of interception
// holds, because that point of interception has restarted and holds none of it.
//
// A triggered POI keeps its tasking in memory, so a restart takes all of it. This
// element's record of what it installed survives, and every claim in that record now
// describes tasking that does not exist. The planning path then finds each triple
// already claimed and installs nothing — so the restarted POI holds no tasking, produces
// no content, and discards the copies it is told to make as untasked, while this element
// goes on reporting the interception as running. Nothing else corrects it: claims are
// released by a withdrawal, and there is nothing left to withdraw.
//
// It is the mirror of the rule that a triggering function which cannot say what a POI
// holds must stay silent and let the fail-safe act. There this element restarted; here
// the POI did, and the conclusion is the same for the same reason — a claim that cannot
// be true must not be treated as one.
//
// Dropping the claims also makes the liveness signal correct again, and that falls out
// rather than needing its own step: keepaliveDue owes a signal for tasking this element
// can name, so an endpoint it now names none for stops being kept alive. That is the
// right answer — keeping a restarted POI alive on the strength of tasking that no longer
// exists is what disables its own fail-safe.
//
// **What this does not do is restore the subscriber's sessions.** Those are lost on the
// same path, which is the pre-existing `// TODO: Session cleanup required` beside the
// caller and a larger problem than this one. What is in scope is that the interception
// bookkeeping stops being the reason re-tasking cannot happen once that TODO is
// addressed: after this, an establishment or a scan at the restarted POI installs the
// trigger instead of skipping it as already claimed.
func (r *triggerRegistry) ForgetPOI(nodeID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	forgotten := 0
	for key := range r.installed {
		_, _, keyNode, ok := parseTriggerKey(key)
		if !ok || keyNode != nodeID {
			continue
		}
		// Deleted outright rather than moved to pending: a pending withdrawal is a
		// trigger this element is still trying to remove *from a POI that holds it*,
		// and retrying against one that restarted would report a fault about tasking
		// that is already gone.
		delete(r.installed, key)
		forgotten++
	}

	return forgotten
}

// take moves every installed trigger whose key matches into pending, and returns
// them.
//
// It does not delete. Deciding to withdraw a trigger is not the same as having
// withdrawn it, and the registry that forgets on the decision has no way to retry
// and no way to know it should: the POI keeps the trigger, keeps duplicating, and
// every participant believes the interception ended. Only an acknowledged
// DeactivateTask deletes (see forgetPending).
//
// Returned sorted by key so a caller's retry order — and a test's — is the same
// every time.
func (r *triggerRegistry) take(match func(warrant, session, nodeID string) bool) []withdrawal {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []withdrawal
	for key, installed := range r.installed {
		warrant, session, nodeID, ok := parseTriggerKey(key)
		if !ok || !match(warrant, session, nodeID) {
			continue
		}
		pkey := pendingKey(key, installed.xid)
		out = append(out, withdrawal{key: pkey, nodeID: nodeID, xid: installed.xid})
		delete(r.installed, key)
		r.pending[pkey] = &pendingWithdrawal{xid: installed.xid, nodeID: nodeID, since: r.timeNow()}
	}
	slices.SortFunc(out, func(a, b withdrawal) int { return strings.Compare(a.key, b.key) })

	return out
}

// takeFailedActivation moves a trigger whose activation did not clearly fail into
// the pending-removal state, and reports whether the caller now owns withdrawing it.
//
// It exists because a failed ActivateTask is not evidence the POI holds nothing.
// Only a refusal the POI *states* is that; a timeout, a lost response or an answer
// this element cannot bind says nothing at all, and the POI may have applied the
// task and answered. Releasing on that outcome leaves a trigger installed that this
// process can no longer name — absent from both maps, so a warrant's withdrawal and
// a session's release each find nothing, and reconciliation only runs at startup.
// The POI then keeps duplicating a subject's content under a warrant that may since
// have been revoked, which is the failure the withdrawal path already exists to
// prevent, reached from the activation side.
//
// Three states are possible when this runs, and each has one right answer:
//
//   - a withdrawal of this exact trigger is already pending — untriggerCC ran while
//     the activation was in flight — and the retry loop already owns it. False: two
//     parties withdrawing one XID is two requests whose answers are
//     indistinguishable.
//   - this trigger is still the claim under its key. Take it.
//   - the key has been re-claimed under a newer XID, so ours is tracked by nothing.
//     Take it anyway, without disturbing the newer claim — that is precisely the
//     orphan this exists to prevent.
func (r *triggerRegistry) takeFailedActivation(key string, xid types.XID) (withdrawal, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pkey := pendingKey(key, xid)
	if _, owned := r.pending[pkey]; owned {
		return withdrawal{}, false
	}

	// Only if it is still ours: a newer claim under this key belongs to a later
	// trigger and deleting it would strand that one instead.
	if r.installed[key].xid == xid {
		delete(r.installed, key)
	}

	_, _, nodeID, ok := parseTriggerKey(key)
	if !ok {
		// Unaddressable, so no withdrawal can be sent anywhere and a pending entry
		// would never clear. Every key this element builds parses; if one ever does
		// not, leaving it out is better than a retry loop with no exit.
		return withdrawal{}, false
	}

	r.pending[pkey] = &pendingWithdrawal{xid: xid, nodeID: nodeID, since: r.timeNow()}

	return withdrawal{key: pkey, nodeID: nodeID, xid: xid}, true
}

// takeOrphan puts a trigger this process never installed — one reconciliation
// found at a POI, left by a previous life — into the same pending-removal state as
// any other withdrawal.
//
// Its key is synthetic: an orphan has no warrant and no session this process can
// name, which is exactly what made it an orphan. Nothing parses a pending key, so
// it need only be unique, and the XID it is built from already is.
func (r *triggerRegistry) takeOrphan(nodeID string, xid types.XID) withdrawal {
	key := pendingKey("orphan|"+nodeID, xid)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending[key] = &pendingWithdrawal{xid: xid, nodeID: nodeID, since: r.timeNow()}

	return withdrawal{key: key, nodeID: nodeID, xid: xid}
}

// forgetPending drops a pending withdrawal the POI has acknowledged — the one
// event that ends this registry's responsibility for a trigger.
func (r *triggerRegistry) forgetPending(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, key)
}

// noteFailure records that a withdrawal attempt failed and reports which
// conditions this attempt newly raises. Each is raised once per pending entry: the
// LIPF needs to hear that a withdrawal failed, and separately that one has been
// outstanding long enough that content is likely still being intercepted without
// authority, but it needs to hear each of them once.
func (r *triggerRegistry) noteFailure(key string) (first, stuck bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.pending[key]
	if !ok {
		return false, false
	}
	if !p.failureReported {
		p.failureReported = true
		first = true
	}
	if !p.stuckReported && r.timeNow().Sub(p.since) >= withdrawalStuckAfter {
		p.stuckReported = true
		stuck = true
	}

	return first, stuck
}

// pendingCount is how many withdrawals are outstanding — the registry's own
// measure of interception it has decided to end and cannot prove has ended.
func (r *triggerRegistry) pendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.pending)
}

// timeNow and sleepFor are the registry's clock. They tolerate a nil hook so a
// registry can be built as a literal without every caller wiring a clock it does
// not care about.
func (r *triggerRegistry) timeNow() time.Time {
	if r.now != nil {
		return r.now()
	}

	return time.Now()
}

func (r *triggerRegistry) sleepFor(d time.Duration) {
	if r.sleep != nil {
		r.sleep(d)

		return
	}
	time.Sleep(d)
}

// withdrawalBackoff is the delay before retry number attempt: 5s doubling to the
// keepalive interval, then steady. Bounded in effort, unbounded in intent — a
// retry that gives up is the defect this exists to fix, arriving later.
func withdrawalBackoff(attempt int) time.Duration {
	d := withdrawalRetryInitial
	for i := 0; i < attempt && d < liKeepaliveInterval; i++ {
		d *= 2
	}
	if d > liKeepaliveInterval {
		return liKeepaliveInterval
	}

	return d
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

// retriggerWarrant reconciles the triggers held for a warrant against the sessions
// its modified task still covers. This is the X1 modification path: the warrant
// remains, so what changes is which of its sessions are tasked for content — and
// a session tasked before and after keeps the trigger it has.
//
// The set of sessions to keep is computed first and the registry is then read
// once, so no trigger installed for the new task can be withdrawn by the old
// task's teardown: under one XID the two are the same key, and they are settled in
// one pass rather than by two events racing.
//
// **It stays on the caller's goroutine, and that is load-bearing.** modifyInterception
// runs this before reportStartOfInterception, whose triggerCC installs triggers for
// sessions the modified task newly covers. Moving this to a goroutine would let that
// installation land between the registry read here and takeForWarrantExcept below — and
// the new trigger's session, absent from `keep`, would then be withdrawn by the pass that
// was meant to leave it alone. Which is the race the ordering above exists to prevent,
// reintroduced by the fix for a different problem.
//
// What made it safe to keep here is that it no longer costs a walk of the session pool:
// the work is bounded by this warrant's own triggers (see sessionsWithTriggers), so a
// provisioning function's answer does not scale with the element's subscriber population.
// Deferring it would have moved that cost rather than removed it.
func (s *subsystem) retriggerWarrant(next types.InterceptTask) {
	if s.triggers == nil {
		return
	}

	var keep map[string]bool
	if next.WantsProduct(types.ProductCC) {
		// Bounded by this warrant's own triggers, not by the session population. See
		// sessionsWithTriggers for why that is the whole of what the caller can act on.
		keep = sessionsCovered(next, s.triggers.sessionsWithTriggers(next.XID))
	}

	pending := s.triggers.takeForWarrantExcept(next.XID, keep)
	if len(pending) == 0 {
		return
	}

	go s.deactivate(pending)
}

// sessionsWithTriggers returns the session references this registry holds triggers for
// under one warrant.
//
// It is what bounds the modification path, and it is bounded correctly rather than
// merely narrowed: `keep` has exactly one consumer, takeForWarrantExcept, which tests
// it while iterating this warrant's installed triggers. A session no trigger exists for
// could therefore never be consulted, so computing an answer for it was work whose
// result was unobservable.
//
// What it replaces walked every live session and took every session's lock, per
// modification — on the X1 request goroutine, so a provisioning function's answer took
// time proportional to the element's subscriber population. That is the question having
// been asked of the wrong structure: which of the triggers this element holds a modified
// task still covers is a fact about the registry, and the registry knows it.
//
// A session served by several UPFs holds a trigger per UPF and appears once here.
func (r *triggerRegistry) sessionsWithTriggers(warrant types.XID) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []string
	for key := range r.installed {
		w, session, _, ok := parseTriggerKey(key)
		if !ok || w != string(warrant) {
			continue
		}
		if !slices.Contains(out, session) {
			out = append(out, session)
		}
	}

	return out
}

// sessionsCovered returns which of refs the given task still targets.
//
// The registry lock is deliberately *not* held across this. plan takes the two the other
// way round — the session's lock first, then the registry's — so holding the registry's
// while acquiring a session's would invert that ordering. The caller reads the refs under
// r.mu, releases it, and only then arrives here.
//
// Each session's identity is read under its own lock, as scanSessions does.
func sessionsCovered(task types.InterceptTask, refs []string) map[string]bool {
	covered := make(map[string]bool, len(refs))
	for _, ref := range refs {
		sc := smfctx.GetSMContext(ref)
		if sc == nil {
			// Released between the registry read and now. Not covered — and withdrawing
			// the trigger of a session that has gone is what that session needs anyway.
			continue
		}

		sc.SMLock.Lock()
		hit := sessionTargets(task, sc)
		sc.SMLock.Unlock()

		if hit {
			covered[ref] = true
		}
	}

	return covered
}

// relabelWarrant carries a change in how a warrant's product is labelled, or in
// where its content goes, to the triggers already installed for it.
//
// The triggers are not torn down and reinstalled. The XID this CC-TF allocated stays,
// the session keeps being intercepted, and a `ModifyTask` carries the new values —
// which is what TS 33.128 table 6.2.3-8 provides for. Withdrawing and reactivating
// would interrupt content the warrant still authorises, to change a label.
//
// Only the fields a POI acts on are compared. A modification that leaves the delivery
// identifier, the correlation value and the destinations alone reaches no POI, because
// there is nothing for one to do differently.
//
// Best-effort per trigger, and deliberately so: a POI that cannot be reached keeps
// labelling content with the superseded identifier, which is a task-level fault the
// LIPF is told about rather than a reason to stop the interception. The alternative —
// withdrawing what cannot be relabelled — would end an interception the warrant still
// authorises because a message did not land.
func (s *subsystem) relabelWarrant(prev, next types.InterceptTask) {
	if s.triggers == nil || !next.WantsProduct(types.ProductCC) {
		return
	}
	// The task's own CorrelationID is deliberately absent from this test. relabel sends
	// installed.correlation — the session's, which is what the POI must stamp so content
	// joins to signalling — so a change to the provisioned value changed nothing at
	// either end and cost an X1 exchange to every POI to do it. The field is now refused
	// at this element anyway (x1.HonoursCorrelationID is not set here), which makes it
	// unreachable rather than merely inert.
	if prev.DeliveryXID() == next.DeliveryXID() &&
		slices.Equal(s.triggers.x3Destinations(prev), s.triggers.x3Destinations(next)) {
		return
	}

	planned := s.triggers.relabel(next, s.triggers.x3Destinations(next))
	if len(planned) == 0 {
		return
	}

	// Ordered per warrant rather than dispatched on a bare goroutine: two
	// modifications in quick succession must leave the POI holding the second one's
	// values, and on bare goroutines they complete in either order with both
	// exchanges acknowledged.
	s.triggers.dispatchForWarrant(next.XID, func() { s.modifyTriggers(planned) })
}

// modifyTriggers sends the ModifyTask for each relabelled trigger.
//
// Off the caller's goroutine as installTriggers is, and for the same reason — these
// are synchronous HTTPS round trips and the caller is the X1 request goroutine —
// but through the registry's per-warrant queue rather than a bare go, because two
// relabels of one warrant must reach the POI in the order the ADMF sent them.
func (s *subsystem) modifyTriggers(planned []plannedTrigger) {
	for _, p := range planned {
		dids, err := s.ensureDestinations(p.endpoint, p.addresses)
		if err != nil {
			s.reportTaskIssue(p.warrant, "the modified X3 delivery destination could not be provisioned at the UPF")
			s.reportUnattributable(err)

			continue
		}
		p.trigger.DIDs = dids

		if err := p.endpoint.req.ModifyTask(p.trigger); err != nil {
			// The trigger stays installed and stays tracked: it is still intercepting,
			// under the label it was given. What the LIPF needs to know is that the
			// element could not apply the modification it acknowledged.
			s.reportTaskIssue(p.warrant, "the UPF did not accept a modification to a content trigger")
			s.reportUnattributable(err)
		}
	}
}

// relabel returns the installed triggers for a warrant, rebuilt with the task's
// current labelling and destinations. It changes nothing in the registry: the trigger
// XIDs and the (warrant, session, UPF) keys are unchanged, because what moved is what
// the POI does with the trigger rather than which trigger it is.
func (r *triggerRegistry) relabel(task types.InterceptTask, addresses []string) []plannedTrigger {
	if len(addresses) == 0 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var out []plannedTrigger
	for key, installed := range r.installed {
		warrant, _, nodeID, ok := parseTriggerKey(key)
		if !ok || warrant != string(task.XID) {
			continue
		}
		endpoint, held := r.endpoints[nodeID]
		if !held {
			continue
		}
		out = append(out, plannedTrigger{
			endpoint:  endpoint,
			key:       key,
			warrant:   task.XID,
			addresses: addresses,
			trigger: x1.Trigger{
				XID: installed.xid,
				// The warrant's new label, and the session's own criterion and
				// correlation unchanged — the trigger still detects the same traffic.
				ProductID:     task.DeliveryXID(),
				CorrelationID: installed.correlation,
				SEID:          installed.seid,
			},
		})
	}
	slices.SortFunc(out, func(a, b plannedTrigger) int { return strings.Compare(a.key, b.key) })

	return out
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

	pending := s.triggers.takeForWarrant(warrant)
	if len(pending) == 0 {
		return
	}

	go s.deactivate(pending)
}
