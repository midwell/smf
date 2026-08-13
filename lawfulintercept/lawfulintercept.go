// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package lawfulintercept is the SMF's Lawful Interception IRI-POI. It receives
// interception tasks over X1 (mutual TLS), matches PDU-session events against
// tasked targets, and delivers the resulting xIRI to an MDF2 over X2. It is
// opt-in: inactive — and silent — unless the SMF is started with LI credentials,
// so an SMF that is not intercepting behaves and looks exactly as before.
package lawfulintercept

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	liasn1 "github.com/omec-project/li/asn1"
	"github.com/omec-project/li/iri"
	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
	"github.com/omec-project/openapi/v2/models"
	smfctx "github.com/omec-project/smf/context"
)

// Config configures the SMF LI IRI-POI. Init is only called when LI is enabled.
type Config struct {
	X1Listen string // address for the X1 provisioning listener, e.g. ":8443"
	MDF2     string // X2 delivery destination (MDF2 "host:port")
	NEID     string // this network element's identifier (echoed in X1 responses)
	Cert     string // X0-pre-provisioned LI PKI: this NE's certificate
	Key      string //                            its private key
	CACert   string //                            the LI CA trust anchor

	// MDF3 is the X3 delivery destination this CC-TF provisions at each triggered
	// CC-POI (TS 33.128 table 6.2.3-6: the trigger names destinations by DID, which
	// the triggering function configures beforehand). The UPF no longer carries an
	// MDF3 address of its own.
	MDF3 string
	// UPFTriggers lists the LI_T3 triggering endpoints of the UPFs this SMF may
	// serve sessions with. A UPF absent from this list cannot be tasked, so CC on a
	// session it serves is reported to the LIPF as a fault rather than skipped.
	UPFTriggers []UPFTrigger

	// Destinations are DID→endpoint mappings this element can resolve without their
	// having been provisioned over X1, for destinations agreed out of band.
	Destinations []Destination

	AdmfURL          string        // ADMF X1 endpoint for NE-initiated issue reports (empty = disabled)
	AdmfID           string        // the responsible ADMF's identifier: authenticates inbound X1 peers and addresses outbound reports (empty accepts any certified ADMF)
	KeepaliveTimeout time.Duration // purge tasking if no X1 message within this (0 = disabled)

	// DeactivateAllTasks and RemoveAllDestinations are the two bulk operations
	// TS 103 221-1 leaves to advance agreement between the operator and the agency.
	// Nil is "no agreement in advance" and leaves the standard's defaults, which
	// li/x1 holds; see x1.BulkOptions.
	DeactivateAllTasks    *bool
	RemoveAllDestinations *bool
}

// Destination is one pre-shared delivery destination: a DID an ADMF's tasks reference,
// and where it points. It resolves exactly as a destination provisioned over X1 does; a
// provisioned entry for the same DID wins.
type Destination struct {
	DID          string
	DeliveryType string // X2Only | X3Only | X2andX3
	Address      string // host:port
}

// sender delivers an xIRI/xCC PDU to an MDF. *x2x3.Client satisfies it; tests
// inject a capturing implementation to assert per-warrant delivery isolation.
type sender interface {
	Send(*x2x3.PDU) error
}

// taskIssueReporter reports a fault with one interception task to the LIPF
// (TS 33.128 clause 5.2.6). An interface, like sender above, so tests can assert
// what the LIPF would be told without standing up an ADMF.
type taskIssueReporter interface {
	NotifyTask(xid, reportType, details string)
}

type subsystem struct {
	store *store.Store
	// senderFor returns the delivery client for one X2 destination address. It is a
	// function rather than a single client because a task's destinations arrive over
	// X1: two warrants may name two agencies' MDF2s, and delivering both to one address
	// is cross-agency disclosure.
	senderFor func(addr string) sender
	// unreachable answers how many of the destinations this element's tasking currently
	// names cannot be reached, and how many of them it has attempted at all — the delivery
	// pool's accounting, scoped to what is in use (see destinationsInUse). A function
	// rather than the pool itself for the same reason senderFor is one: a test states a
	// delivery condition without an MDF to take away.
	unreachable func() (unreachable, inUse int)
	// mdf2 is the configured X2 endpoint, used only for a task that names no
	// destination this element can resolve.
	mdf2     string
	iriCtx   *liasn1.Context
	neID     string
	reporter *x1.Reporter // nil when NE-initiated reporting is not configured
	// taskReporter reports per-task faults; nil when no ADMF is configured.
	taskReporter taskIssueReporter
	// triggers is the CC Triggering Function's state: one X1 client per UPF, plus
	// the trigger tasks installed there. Nil when no triggering endpoints are
	// configured, in which case CC duplication is still applied but the UPF is
	// never told whose warrant it serves — so it delivers nothing.
	triggers *triggerRegistry
}

// deliveryFault is what this element can answer about itself when an ADMF asks for its
// status: whether the mediation functions it delivers to are reachable right now.
//
// Only the delivery clients know this — li/x1 holds the tasking, not the sockets — so
// without it the element would answer that no observable condition holds however long it had
// been failing to deliver. That answer is true and useless, and it is ignored exactly as
// fast as an element that always reports itself faulty.
//
// It answers from what the last delivery attempt established and dials nothing, because it
// runs on the X1 request goroutine: a probe that went looking would hold up a provisioning
// function's answer.
//
// This is the element's own status, so it covers this POI's X2 delivery only. Whether the
// UPF it triggers can reach its MDF3 is that element's status to report, and it has an X1
// interface of its own to report it on.
//
// It asks only about the destinations this element's *current* tasking names — see
// destinationsInUse — so a warrant's withdrawal takes its destination out of the answer with
// it.
//
// A subsystem with no delivery accounting reports nothing rather than panicking on the X1
// request path — an element that cannot say is not an element that is broken.
func (s *subsystem) deliveryFault() *x1.X1Error {
	if s.unreachable == nil {
		return nil
	}

	return x1.MDFUnreachableProbe(s.unreachable)()
}

// destinationsInUse is where this element's xIRI currently goes: the X2 endpoints the tasking
// it holds names, and the configured MDF2 for a task that names nothing this element can
// resolve.
//
// It exists because a delivery client outlives the warrant that created it. A destination
// whose last delivery failed and whose warrant was then deactivated can never be delivered to
// again, so nothing would ever clear it — the element would report itself faulty for the life
// of the process, including while holding no tasking at all. Scoping the question to what is
// in use is what keeps that probe from sticking on.
func (s *subsystem) destinationsInUse() []string {
	var addrs []string
	for _, t := range s.store.Snapshot() {
		if !t.WantsProduct(types.ProductIRI) {
			continue
		}
		addrs = append(addrs, s.x2Destinations(t)...)
	}

	return addrs
}

// active holds the running subsystem, or nil when LI is not configured.
var active atomic.Pointer[subsystem]

// newX1Server builds this element's X1 provisioning endpoint from its configuration.
//
// Separate from Init so that what an operator's configuration does to the X1 server can be
// asserted against the server this element actually runs, rather than against a second
// copy of the same wiring written in a test — which is where a configured policy quietly
// stops being applied.
func newX1Server(st *store.Store, cfg Config, sub *subsystem) *x1.Server {
	// OnActivate/OnDeactivate scan already-established sessions when a warrant is
	// (de)tasked mid-session: emit the "start with established PDU
	// session" xIRI and (de)activate CC duplication on live sessions.
	// WithADMF holds X1 peers to the responsible ADMF's identity: a certificate
	// from the LI CA authenticates a peer, but only this identifier may task us
	// (TS 103 221-1 clause 8.2.4 + error 1040).
	// A peer that fails that check is refused, and — since this plane deliberately
	// logs nothing — would otherwise be refused in complete silence. The ADMF is the
	// only party entitled to hear that someone is trying to task its network
	// elements under an identity that is not theirs.
	opts := []x1.Option{
		x1.WithADMF(cfg.AdmfID),
		x1.WithConfiguredDestinations(configuredDestinations(cfg.Destinations, sub.reporter)...),
		// The conditions this POI can observe about itself, which li/x1 cannot: see
		// subsystem.deliveryFault.
		x1.WithFaultProbes(sub.deliveryFault),
		x1.OnActivate(sub.reportStartOfInterception),
		x1.OnDeactivate(sub.reportDeactivation),
		x1.OnAuthFailure(func(code int) {
			if sub.reporter != nil {
				sub.reporter.Notify(x1.NEIssueX1AuthFailed,
					fmt.Sprintf("X1 provisioning refused: peer failed authentication (error %d)", code))
			}
		}),
	}
	// The two bulk operations the standard settles by advance agreement rather than by
	// what the element is. Unset leaves its defaults; li/x1 owns what unset means.
	opts = append(opts, x1.BulkOptions(cfg.DeactivateAllTasks, cfg.RemoveAllDestinations)...)

	return x1.NewServer(st, cfg.NEID, opts...)
}

// Init starts the SMF LI IRI-POI: it loads the LI credentials, opens the X1
// listener (mutual TLS), and prepares X2 delivery to the MDF2. Call it once at
// SMF startup, only when LI is configured.
func Init(cfg Config) error {
	mat, err := mtls.Load(cfg.Cert, cfg.Key, cfg.CACert)
	if err != nil {
		return err
	}
	st := store.New()
	var reporter *x1.Reporter
	if cfg.AdmfURL != "" {
		reporter = x1.NewReporter(cfg.AdmfURL, cfg.AdmfID, cfg.NEID, mat.ClientTLS())
	}
	// Deliver X2 asynchronously: the Report* hooks run on the PDU-session
	// signalling goroutine while sc.SMLock is held, so a slow or unreachable MDF2
	// must never block them — that is an availability risk and a target-observable
	// timing side channel, so delivery is asynchronous by design.
	// Worker delivery failures surface to the ADMF over X1 (throttled, NE-level,
	// no target id), never to a general log.
	//
	// One client per destination address, created on first use: a task carries the
	// endpoints its product goes to, and TS 33.128 marks them mandatory, so this
	// element cannot know them at startup.
	pool := x2x3.NewPool(mat.ClientTLS(),
		func(error) {
			if reporter != nil {
				reporter.Notify(x1.NEIssueMDFUnreachable, "MDF2 X2 delivery failed")
			}
		},
		nil, // drops are covered by the same MDF-unreachable report from the worker
	)
	sub := &subsystem{
		store:     st,
		senderFor: func(addr string) sender { return pool.For(addr) },
		mdf2:      cfg.MDF2,
		iriCtx:    iri.NewContext(),
		neID:      cfg.NEID,
		reporter:  reporter,
	}
	// Assigned after construction because it reads the subsystem it belongs to: the pool
	// knows what each destination's last delivery established, and only the subsystem knows
	// which destinations the tasking still names.
	sub.unreachable = func() (int, int) { return pool.UnreachableAmong(sub.destinationsInUse()) }
	// Assign the interface only when a reporter exists: a typed-nil would pass the
	// nil check in reportTaskIssue and then panic on use.
	if reporter != nil {
		sub.taskReporter = reporter
	}
	if len(cfg.UPFTriggers) > 0 {
		var triggers *triggerRegistry
		triggers, err = newTriggerRegistry(cfg, mat.ClientTLS())
		if err != nil {
			// A CC-TF whose triggering configuration is ambiguous cannot task the POI
			// it displaced, so content for sessions that UPF serves would be
			// duplicated and then dropped as unattributable. Refusing to start LI is
			// the fail-closed choice, and the LIPF is told because the alternative is
			// an ADMF that believes content interception is available when it is not.
			if reporter != nil {
				reporter.Notify(x1.NEIssueInvalidConfig,
					"content triggering configuration is ambiguous; no content interception is possible")
			}

			return err
		}
		sub.triggers = triggers
		// A POI may still hold triggers from this process's previous life, which it
		// has no record of and could never withdraw — including after the warrant is
		// revoked.
		go sub.reconcileTriggers()
	}
	x1srv := newX1Server(st, cfg, sub)
	// Bind the X1 listener synchronously so a bind/permission failure is reported
	// to the caller, rather than being swallowed in a goroutine while LI already
	// looks enabled (active.Store below) — otherwise no X1 tasking can be received.
	// ListenConfig.Listen rather than net.Listen so the listen carries a context
	// (the linter's noctx rule); the bind is otherwise unchanged.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", cfg.X1Listen)
	if err != nil {
		if sub.reporter != nil {
			sub.reporter.Notify(x1.NEIssueX1ListenFailed, "X1 listener bind failed")
		}
		return fmt.Errorf("lawful interception: X1 listen on %s: %w", cfg.X1Listen, err)
	}
	// NewListener supplies the properties every X1 endpoint needs and none of the
	// three network functions should be trusted to remember separately: a discarded
	// error log and per-phase timeouts, without which an unauthenticated peer can
	// hold connections open until this element can no longer be untasked.
	srv := x1.NewListener(x1srv, mat.ServerTLS())
	// Certificates come from TLSConfig, so the file arguments are empty. ServeTLS
	// blocks until the listener closes; the bind already succeeded above.
	//nolint:errcheck // serve-until-close; a bind failure already surfaced above
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	// Keepalive fail-safe: purge tasking if the ADMF goes silent (TS 103 221-1).
	// A nil stop channel: the fail-safe runs for as long as this element can hold
	// tasking, which is the whole point of it.
	if cfg.KeepaliveTimeout > 0 {
		go x1srv.WatchKeepalive(cfg.KeepaliveTimeout, nil)
	}
	active.Store(sub)
	// Tasking lives in memory, so this element has just discarded every warrant it
	// held. Nothing else tells the ADMF that — it goes on believing the
	// interceptions it provisioned are running — and the standard's audit path is a
	// query it has to think to make. Saying so on the way up is the one push signal
	// available.
	if reporter != nil && st.Len() == 0 {
		reporter.Notify(x1.NEIssueTaskingAbsent,
			"network function started with interception enabled and no tasking present")
	}
	return nil
}

// ReportEstablishment emits an SMFPDUSessionEstablishment xIRI for sc if it
// matches an active task. No-op and silent when LI is inactive or sc is not a
// target.
//
// Call this once the UPF has answered the PFCP Session Establishment Request, not
// when the SBI create returns. The record carries the session's F-TEID and its X2
// correlation identifier is the F-SEID, and neither exists until the UPF has
// assigned them — emitting at the SBI point produced a record with a zero TEID
// and a zero correlation, so the one record that describes the session to the MDF
// was the one record that could not be joined to that session's content.
//
// Emitted at most once per session: a session spanning several UPFs draws an
// establishment response from each. Caller holds sc.SMLock.
func ReportEstablishment(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}

	if sc.LiEstablishmentReported {
		return
	}

	sc.LiEstablishmentReported = true

	sub.deliverIRI(sub.matchingTasks(sc), correlationOf(sc), smfEstablishment(sc))
}

// ReportModification emits an SMFPDUSessionModification xIRI for sc if it
// matches an active task. No-op and silent otherwise.
func ReportModification(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	sub.deliverIRI(sub.matchingTasks(sc), correlationOf(sc), smfModification(sc))
}

// ReportRelease emits an SMFPDUSessionRelease xIRI for sc if it matches an
// active task. No-op and silent otherwise.
func ReportRelease(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	// A single teardown can reach both the update-initiated delete and the
	// dedicated release handler; emit the release xIRI only once.
	// Both call sites hold sc.SMLock, so this check-and-set is safe.
	if sc.LiReleaseReported {
		return
	}
	sc.LiReleaseReported = true
	sub.deliverIRI(sub.matchingTasks(sc), correlationOf(sc), smfRelease(sc))
}

// ApplyCCTrigger is the SMF Content-of-Communication Triggering Function. When
// the session's target has an active task requesting CC product, it marks the
// session's forwarding FARs for user-plane duplication (ApplyAction DUPL +
// Duplicating Parameters to the LI Function) so the serving UPF(s) tee the
// traffic to the MDF3. No-op and silent when LI is inactive.
//
// It walks the session's whole data-path pool, so duplication is applied on
// every UPF serving the target (multi-slice / UPF scaling).
//
// SCOPE: this runs from SendPFCPRules at PDU-session establishment, so it triggers
// CC for sessions established after tasking. The complementary case — a warrant
// (de)tasked while the session is already up — is handled by the X1
// OnActivate/OnDeactivate hooks (reportStartOfInterception / reportDeactivation),
// which re-evaluate CC and re-send a PFCP modification.
func ApplyCCTrigger(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil || sc.Tunnel == nil {
		return
	}
	cc := sub.ccTasked(sc)
	forEachForwardingFAR(sc, func(far *smfctx.FAR) {
		if far.ApplyAction.Dupl == cc {
			return
		}
		setDuplication(far, cc)
		// At establishment the FAR is still RULE_INITIAL and is sent as a Create
		// FAR carrying DUPL. On a re-invocation of SendPFCPRules for an already-
		// installed session (ULCL path add / HO path-switch) it is RULE_CREATE, so
		// mark it RULE_UPDATE — otherwise the modification builder's state switch
		// skips it and the DUPL flip is never sent to the UPF.
		if far.State == smfctx.RULE_CREATE {
			far.State = smfctx.RULE_UPDATE
		}
	})
}

// forEachForwardingFAR invokes fn for every forwarding FAR across all of sc's
// data paths — the ones actually carrying the target's user-plane traffic, on
// every UPF serving the session. Caller holds sc.SMLock; sc.Tunnel must be non-nil.
func forEachForwardingFAR(sc *smfctx.SMContext, fn func(*smfctx.FAR)) {
	for _, dp := range sc.Tunnel.DataPathPool {
		for node := dp.FirstDPNode; node != nil; node = node.Next() {
			for _, tun := range []*smfctx.GTPTunnel{node.UpLinkTunnel, node.DownLinkTunnel} {
				if tun == nil {
					continue
				}
				for _, pdr := range tun.PDR {
					if pdr != nil && pdr.FAR != nil && pdr.FAR.ApplyAction.Forw {
						fn(pdr.FAR)
					}
				}
			}
		}
	}
}

// setDuplication turns user-plane duplication on or off for one forwarding FAR.
// When on, the copy is destined for the LI Function; the SD-Core UPF CC-POI
// frames and ships it over X3 natively, so no OuterHeaderCreation tunnel is set.
func setDuplication(far *smfctx.FAR, on bool) {
	far.ApplyAction.Dupl = on
	if on {
		far.DuplicatingParameters = &smfctx.DuplicatingParameters{
			DestinationInterface: smfctx.DestinationInterface{InterfaceValue: smfctx.DestinationInterfaceLIFunction},
		}
	} else {
		far.DuplicatingParameters = nil
	}
}

// ccTasked reports whether any active task targeting sc requests CC product.
func (s *subsystem) ccTasked(sc *smfctx.SMContext) bool {
	for _, t := range s.matchingTasks(sc) {
		if t.WantsProduct(types.ProductCC) {
			return true
		}
	}
	return false
}

// sessionModifier sends a PFCP session modification carrying sc's current FAR
// state. It is injected by the service layer (SetSessionModifier) because this
// package is imported by smf/producer and so cannot call
// producer.SendPfcpSessionModifyReq directly. While nil (e.g. in tests) the
// mid-session CC hooks still update FAR state but send nothing.
var sessionModifier func(*smfctx.SMContext) error

// SetSessionModifier installs the PFCP-modification hook used by mid-session CC
// (de)activation. Call once at start-up, before the X1 server accepts tasking.
func SetSessionModifier(fn func(*smfctx.SMContext) error) {
	sessionModifier = fn
}

// reportStartOfInterception is the X1 OnActivate hook: when a warrant is tasked
// for a UE that already has a live PDU session, emit the "start with established
// PDU session" xIRI (if IRI is wanted) and switch on CC duplication (if CC is
// wanted). It runs on live sessions the target already has; sessions established
// later are handled at establishment by ReportEstablishment / ApplyCCTrigger.
func (s *subsystem) reportStartOfInterception(task types.InterceptTask) {
	wantIRI := task.WantsProduct(types.ProductIRI)
	s.scanSessions(task, func(sc *smfctx.SMContext) any {
		var event any
		// uEEndpoint is mandatory in this record, and an empty list would assert
		// the session has no endpoint address. A session with no address assigned
		// is not one this record can describe, so report nothing for it rather
		// than something untrue — the CC work below is unaffected either way.
		if wantIRI && ueEndpoint(sc) != nil {
			event = smfStartOfInterception(sc)
		}
		if s.applyCC(sc) {
			s.modifySession(sc)
		}
		// Task the serving UPFs for this warrant too: the FARs now duplicate, but
		// without a trigger the copies carry no warrant identity.
		s.triggerCC(sc)
		return event
	})
}

// reportDeactivation is the X1 OnDeactivate hook: when a warrant is removed, undo
// the CC duplication it caused on the target's live sessions. It re-evaluates
// against the remaining task set, so duplication is only cleared once no CC task
// still targets the session (correct under overlapping multi-agency warrants).
// IRI needs no undo, so a pure-IRI deactivation is a no-op.
func (s *subsystem) reportDeactivation(task types.InterceptTask) {
	if !task.WantsProduct(types.ProductCC) {
		return
	}
	s.scanSessions(task, func(sc *smfctx.SMContext) any {
		if s.applyCC(sc) {
			s.modifySession(sc)
		}
		return nil
	})
	// Withdraw this warrant's triggers wherever they were installed. Unlike the
	// FAR state, which is re-evaluated against the remaining task set, a trigger
	// belongs to exactly one warrant and goes with it.
	s.untriggerWarrant(task.XID)
}

// scanSessions finds every live session targeted by task, then processes each in
// a background goroutine (holding sc.SMLock) — off the X1 request goroutine, so a
// slow PFCP round-trip never delays the X1 response. fn returns an xIRI event to
// deliver after the lock is released, or nil. The target match is done under the
// per-session lock because it reads the session's identity fields.
func (s *subsystem) scanSessions(task types.InterceptTask, fn func(*smfctx.SMContext) any) {
	var matched []*smfctx.SMContext
	smfctx.RangeSMContexts(func(sc *smfctx.SMContext) bool {
		sc.SMLock.Lock()
		hit := sessionTargets(task, sc)
		sc.SMLock.Unlock()
		if hit {
			matched = append(matched, sc)
		}
		return true
	})
	if len(matched) == 0 {
		return
	}
	go func() {
		for _, sc := range matched {
			sc.SMLock.Lock()
			event := fn(sc)
			corr := correlationOf(sc) // read under the lock (reads sc.PFCPContext)
			sc.SMLock.Unlock()
			if event != nil {
				s.deliverIRI([]types.InterceptTask{task}, corr, event)
			}
		}
	}()
}

// applyCC makes sc's forwarding FARs match whether the target is currently
// CC-tasked, marking any FAR it changes RULE_UPDATE so a PFCP modification
// re-sends it. It returns whether anything changed (a modification is due).
// Caller holds sc.SMLock.
func (s *subsystem) applyCC(sc *smfctx.SMContext) bool {
	if sc.Tunnel == nil {
		return false
	}
	want := s.ccTasked(sc)
	changed := false
	forEachForwardingFAR(sc, func(far *smfctx.FAR) {
		if far.ApplyAction.Dupl == want {
			return
		}
		setDuplication(far, want)
		far.State = smfctx.RULE_UPDATE
		changed = true
	})
	return changed
}

// modifySession fires the injected PFCP-modification hook for sc, silently (any
// failure surfaces through normal PFCP handling, never a target-revealing log).
// Caller holds sc.SMLock.
func (s *subsystem) modifySession(sc *smfctx.SMContext) {
	if sessionModifier != nil {
		//nolint:errcheck // failure surfaces through normal PFCP handling, never a target-revealing log
		_ = sessionModifier(sc)
	}
}

// sessionTargets reports whether task's target identifier matches one of sc's
// identifiers. Caller holds sc.SMLock (targetsOf reads sc's identity fields).
func sessionTargets(task types.InterceptTask, sc *smfctx.SMContext) bool {
	return task.TargetsAny(targetsOf(sc))
}

// deliverIRI encodes event once and delivers it as an X2 xIRI to every task in
// tasks that wants IRI product. It is silent on any error (encoding or
// delivery) so that interception can never be inferred from SMF behaviour.
func (s *subsystem) deliverIRI(tasks []types.InterceptTask, corr [8]byte, event any) {
	if len(tasks) == 0 {
		return
	}
	payload, err := iri.EncodeXIRI(s.iriCtx, event)
	if err != nil {
		return
	}
	for _, t := range tasks {
		if !t.WantsProduct(types.ProductIRI) {
			continue
		}
		for _, addr := range s.x2Destinations(t) {
			client := s.senderFor(addr)
			if client == nil {
				continue
			}
			// Delivery is asynchronous (see Init): Send enqueues and returns, so this
			// signalling path never blocks on the MDF; delivery failures are reported
			// to the ADMF over X1 from the delivery worker, not here. The correlation
			// ID lets the MDF join this xIRI to the session's xCC.
			//nolint:errcheck // async enqueue; delivery failures report via the worker, not here
			_ = client.Send(&x2x3.PDU{
				Type:          x2x3.PDUTypeX2,
				PayloadFormat: x2x3.PayloadFormat3GPP33128,
				Direction:     x2x3.DirectionNotApplicable,
				// A provisioned ProductID replaces the task XID in the PDU header
				// (TS 103 221-1 clause 6.2.1.2), so product is labelled with the
				// warrant an ADMF names rather than with the task carrying it.
				XID:           parseXID(t.DeliveryXID()),
				CorrelationID: corr,
				Payload:       payload,
			})
		}
	}
}

// x2Destinations is where this task's xIRI goes.
//
// The task's own destinations first, which is what TS 33.128 requires — table 6.2.3-0A,
// "ActivateTask message for SMF IRI-POI, CC-TF and IRI-TF", marks ListOfDIDs mandatory
// and says the endpoints "shall be configured using the CreateDestination message …
// prior to first use". The configured MDF2 serves only a task that named nothing this
// element could resolve, which is the case every deployment predating that requirement
// is in.
func (s *subsystem) x2Destinations(t types.InterceptTask) []string {
	if addrs := t.DeliveryAddresses(types.DeliveryX2); len(addrs) > 0 {
		return addrs
	}
	if s.mdf2 == "" {
		return nil
	}

	return []string{s.mdf2}
}

// correlationOf returns the X2 correlation identifier for sc's session: the
// serving UPF's F-SEID encoded big-endian — the same value and byte order the UPF
// stamps on the session's X3 xCC, so the MDF can join a session's xIRI and xCC.
// Best-effort: zero before the PFCP session is
// established (the UPF-assigned SEID is not yet known), matching servingUPFTEID's
// best-effort caveat. Caller holds sc.SMLock.
func correlationOf(sc *smfctx.SMContext) [8]byte {
	var corr [8]byte
	binary.BigEndian.PutUint64(corr[:], servingUPFSEID(sc))
	return corr
}

// servingUPFSEID returns the serving UPF's assigned F-SEID for sc's default data
// path (the SMF's RemoteSEID for that UPF's PFCP session), or 0 if not yet
// established. Uses the same default-path selector as servingUPFTEID so a
// multi-path (ULCL) session anchors deterministically on the N3 UPF.
func servingUPFSEID(sc *smfctx.SMContext) uint64 {
	if sc.Tunnel == nil {
		return 0
	}
	dp := sc.Tunnel.DataPathPool.GetDefaultPath()
	if dp == nil {
		return 0
	}
	node := dp.FirstDPNode
	if node == nil || node.UPF == nil {
		return 0
	}
	key := node.UPF.NodeID.ResolveNodeIdToIp().String()
	if pfcpCtx, ok := sc.PFCPContext[key]; ok && pfcpCtx != nil {
		return pfcpCtx.RemoteSEID
	}
	return 0
}

// matchingTasks returns the active tasks targeting any of sc's identifiers,
// de-duplicated by task id.
func (s *subsystem) matchingTasks(sc *smfctx.SMContext) []types.InterceptTask {
	var out []types.InterceptTask
	seen := map[types.XID]bool{}
	for _, id := range targetsOf(sc) {
		for _, t := range s.store.Match(id) {
			if !seen[t.XID] {
				seen[t.XID] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// targetsOf returns sc's known 5G target identifiers, with the SMF's "type-"
// prefixes stripped to the bare value the X1 tasking uses.
func targetsOf(sc *smfctx.SMContext) []types.TargetIdentifier {
	var ids []types.TargetIdentifier
	if v := afterPrefix(sc.Supi, "imsi-", "nai-"); v != "" {
		ids = append(ids, types.TargetIdentifier{Type: types.TargetSUPI, Value: v})
	}
	if v := afterPrefix(sc.Pei, "imeisv-", "imei-"); v != "" {
		ids = append(ids, types.TargetIdentifier{Type: types.TargetPEI, Value: v})
	}
	if v := afterPrefix(sc.Gpsi, "msisdn-", "extid-"); v != "" {
		ids = append(ids, types.TargetIdentifier{Type: types.TargetGPSI, Value: v})
	}
	return ids
}

// smfEstablishment maps an SMContext to a TS 33.128 SMFPDUSessionEstablishment
// record. Deferred optionals (deeper subtrees): uEEndpoint, location, and the
// long tail.
func smfEstablishment(sc *smfctx.SMContext) iri.SMFPDUSessionEstablishment {
	return iri.SMFPDUSessionEstablishment{
		SUPI:           supiChoice(sc),
		PEI:            peiChoice(sc),
		GPSI:           gpsiChoice(sc),
		PDUSessionID:   iri.PDUSessionID(sc.PDUSessionID),
		GTPTunnelID:    servingUPFTEID(sc),
		PDUSessionType: iri.PDUSessionType(sc.SelectedPDUSessionType),
		SNSSAI:         snssai(sc),
		UEEndpoint:     ueEndpoint(sc),
		DNN:            iri.DNN(sc.Dnn),
		RequestType:    requestType(sc),
		AccessType:     accessType(sc),
	}
}

// ueEndpoint is the address assigned to the subject's session — distinct from
// servingUPFTEID, which carries the serving UPF's tunnel endpoint. Reporting only
// the latter tells an agency which network element carried the traffic but not
// which address the target was using, and the second is what an investigation
// correlates against.
//
// Nil when no address has been assigned, so the record omits the field rather
// than claiming the session has no endpoint address.
func ueEndpoint(sc *smfctx.SMContext) []any {
	if sc == nil || sc.PDUAddress == nil {
		return nil
	}
	return iri.UEEndpoint(sc.PDUAddress.Ip)
}

// smfStartOfInterception maps an SMContext to a TS 33.128
// SMFStartOfInterceptionWithEstablishedPDUSession record (XIRIEvent [9]), emitted
// when a warrant is activated for a UE whose PDU session is already up. Same shape
// as the establishment record, but requestType marks the session as pre-existing.
func smfStartOfInterception(sc *smfctx.SMContext) iri.SMFStartOfInterceptionWithEstablishedPDUSession {
	return iri.SMFStartOfInterceptionWithEstablishedPDUSession{
		SUPI:           supiChoice(sc),
		PEI:            peiChoice(sc),
		GPSI:           gpsiChoice(sc),
		PDUSessionID:   iri.PDUSessionID(sc.PDUSessionID),
		GTPTunnelID:    servingUPFTEID(sc),
		PDUSessionType: iri.PDUSessionType(sc.SelectedPDUSessionType),
		SNSSAI:         snssai(sc),
		UEEndpoint:     ueEndpoint(sc),
		DNN:            iri.DNN(sc.Dnn),
		RequestType:    iri.SMRequestExisting,
		AccessType:     accessType(sc),
	}
}

// smfModification maps an SMContext to a TS 33.128 SMFPDUSessionModification
// record. Only requestType is mandatory.
func smfModification(sc *smfctx.SMContext) iri.SMFPDUSessionModification {
	return iri.SMFPDUSessionModification{
		SUPI:         supiChoice(sc),
		PEI:          peiChoice(sc),
		GPSI:         gpsiChoice(sc),
		SNSSAI:       snssai(sc),
		RequestType:  iri.SMRequestModification,
		AccessType:   accessType(sc),
		PDUSessionID: iri.PDUSessionID(sc.PDUSessionID),
	}
}

// smfRelease maps an SMContext to a TS 33.128 SMFPDUSessionRelease record.
// Volume counters are optional and deferred (they live on the UPF's URRs).
func smfRelease(sc *smfctx.SMContext) iri.SMFPDUSessionRelease {
	return iri.SMFPDUSessionRelease{
		SUPI:         supiChoice(sc),
		PEI:          peiChoice(sc),
		GPSI:         gpsiChoice(sc),
		PDUSessionID: iri.PDUSessionID(sc.PDUSessionID),
	}
}

// servingUPFTEID returns the N3 GTP-U F-TEID (uplink TEID + serving UPF IP) of
// the session's default data path, best-effort: a zero F-TEID if the tunnel is
// not yet set up. It uses the canonical default-path selector (the same one the
// PFCP establishment-response handler uses to find the N3 UPF) rather than an
// arbitrary map entry, so a multi-path (ULCL) session yields the anchoring path
// deterministically. The PDU-session establishment record carries this mandatory
// field so the MDF can correlate the user plane.
func servingUPFTEID(sc *smfctx.SMContext) iri.FTEID {
	var f iri.FTEID
	if sc.Tunnel == nil {
		return f
	}
	dp := sc.Tunnel.DataPathPool.GetDefaultPath()
	if dp == nil {
		return f
	}
	node := dp.FirstDPNode
	if node == nil || node.UpLinkTunnel == nil || node.UPF == nil {
		return f
	}
	f.TEID = int64(node.UpLinkTunnel.TEID)
	if ip := net.ParseIP(node.UPF.GetUPFIP()); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			f.IPv4Address = v4
		} else if v16 := ip.To16(); v16 != nil {
			f.IPv6Address = v16
		}
	}
	return f
}

// requestType maps the 5GSM request type the AMF supplied to the TS 33.128
// enumeration. These records go to a law-enforcement agency, so reporting every
// session as an initial request — which is what a hard-coded value amounted to —
// misstates whether the UE asked for a new session or resumed an existing one,
// and hides an emergency session entirely.
func requestType(sc *smfctx.SMContext) iri.FiveGSMRequestType {
	switch sc.RequestType {
	case models.REQUESTTYPE_EXISTING_PDU_SESSION:
		return iri.SMRequestExisting
	case models.REQUESTTYPE_INITIAL_EMERGENCY_REQUEST:
		return iri.SMRequestInitialEmergency
	case models.REQUESTTYPE_EXISTING_EMERGENCY_PDU_SESSION:
		return iri.SMRequestExistingEmergency
	default:
		return iri.SMRequestInitial
	}
}

// accessType maps the session's access network type to the TS 33.128
// enumeration, for the same reason: a session over non-3GPP access was reported
// as a 3GPP one.
func accessType(sc *smfctx.SMContext) iri.AccessType {
	if sc.AnType == models.ACCESSTYPE_NON_3_GPP_ACCESS {
		return iri.AccessNonThreeGPP
	}
	return iri.AccessThreeGPP
}

// snssai maps the SMContext's S-NSSAI to the iri form (SST + optional SD). A nil
// or SST-0 S-NSSAI yields the zero value, which the codec omits (the record's
// S-NSSAI is optional).
func snssai(sc *smfctx.SMContext) iri.SNSSAI {
	if sc.Snssai == nil {
		return iri.SNSSAI{}
	}
	s := iri.SNSSAI{SliceServiceType: int(sc.Snssai.Sst)}
	if sc.Snssai.Sd != nil {
		if sd, err := hex.DecodeString(*sc.Snssai.Sd); err == nil && len(sd) == 3 {
			s.SliceDifferentiator = sd
		}
	}
	return s
}

// supiChoice returns sc's SUPI as the iri "supi" CHOICE arm (IMSI or NAI), or
// nil when the SMF holds no SUPI in a form we can map.
func supiChoice(sc *smfctx.SMContext) any {
	if v, ok := strings.CutPrefix(sc.Supi, "imsi-"); ok {
		return iri.IMSI(v)
	}
	if v, ok := strings.CutPrefix(sc.Supi, "nai-"); ok {
		return iri.NAI(v)
	}
	return nil
}

// peiChoice returns sc's PEI as the iri "pei" CHOICE arm (IMEI or IMEISV), or nil.
func peiChoice(sc *smfctx.SMContext) any {
	if v, ok := strings.CutPrefix(sc.Pei, "imeisv-"); ok {
		return iri.IMEISV(v)
	}
	if v, ok := strings.CutPrefix(sc.Pei, "imei-"); ok {
		return iri.IMEI(v)
	}
	return nil
}

// gpsiChoice returns sc's GPSI as the iri "gpsi" CHOICE arm (MSISDN), or nil.
func gpsiChoice(sc *smfctx.SMContext) any {
	if v, ok := strings.CutPrefix(sc.Gpsi, "msisdn-"); ok {
		return iri.MSISDN(v)
	}
	return nil
}

// parseXID converts a task's X1 identifier to the 16-byte XID carried in the
// X2 PDU header. It delegates to types.XID.Bytes so the conversion lives in one
// place across the POIs and the triggered CC-POI in the UPF.
func parseXID(xid types.XID) [16]byte {
	return xid.Bytes()
}

// afterPrefix returns s with the first matching prefix removed, or "" if none
// match (an identifier we cannot map is treated as not present).
func afterPrefix(s string, prefixes ...string) string {
	for _, p := range prefixes {
		if v, ok := strings.CutPrefix(s, p); ok {
			return v
		}
	}
	return ""
}

// configuredDestinations maps the pre-shared destinations from configuration onto the
// form the X1 server resolves them in, and tells the ADMF about any it cannot use.
//
// An entry that does not resolve is not a small mistake: a task naming that DID falls
// through to the configured default endpoint instead, so an operator's typo quietly sends
// one agency's product to another's address. There is no general log to say so on — this
// plane deliberately writes to none — and the count is all the ADMF needs, since the
// entries themselves are the operator's configuration and not the ADMF's business.
func configuredDestinations(dests []Destination, reporter *x1.Reporter) []x1.ConfiguredDestination {
	out := make([]x1.ConfiguredDestination, 0, len(dests))
	var rejected int
	for _, d := range dests {
		entry := x1.ConfiguredDestination{DID: d.DID, DeliveryType: d.DeliveryType, Address: d.Address}
		if entry.Valid() != nil {
			rejected++

			continue
		}
		out = append(out, entry)
	}
	if rejected > 0 {
		reporter.Notify(x1.NEIssueInvalidConfig, fmt.Sprintf(
			"%d configured delivery destination(s) are unusable and were dropped; "+
				"a task naming one will be delivered to the default endpoint instead", rejected))
	}

	return out
}
