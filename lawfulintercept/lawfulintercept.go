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
	"errors"
	"fmt"
	"net"
	"slices"
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

	// The three settings of the TS 103 221-2 clause 6.2.4 keepalive mechanism, as the
	// operator wrote them. Parsed here rather than by the caller because an unusable
	// value is reported to the ADMF over X1, and the reporter does not exist until
	// this subsystem starts.
	X2X3KeepaliveEnabled *bool
	X2X3KeepaliveTimeP1  string
	X2X3KeepaliveTimeP2  string

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

// errNoElementIdentifier means the deployment configured interception without the
// identifier this element asserts on X1, which is also the Network Function ID every
// record it delivers has to carry (TS 33.128 table 5.3.1-2).
var errNoElementIdentifier = errors.New("li: no network element identifier configured")

// smfInterceptionPoint is the Interception Point ID every xIRI from this element
// carries (ETSI TS 103 221-2 clause 5.3.8): it names the POI within the network
// function. The SMF also hosts the CC and IRI triggering functions, but a triggering
// function delivers no product, so there is one point of interception here.
const smfInterceptionPoint = "SMF-IRI-POI"

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
	mdf2   string
	iriCtx *liasn1.Context
	neID   string
	// ids supplies the conditional attributes that belong to this element rather than
	// to the task — its two identities and the per-context sequence numbering — shared
	// with the AMF's IRI-POI and the UPF's CC-POI through li/x2x3.
	ids      *x2x3.Identity
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
	// OnTaskChange scans already-established sessions when a warrant is (de)tasked
	// or modified mid-session: emit the "start with established PDU session" xIRI
	// and (de)activate CC duplication on live sessions.
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
		x1.OnTaskChange(sub.applyTaskChange),
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
	// Without an identifier for this network element, product would reach a mediation
	// function that cannot attribute it to the element that produced it. Interception
	// does not start; the SMF itself carries on serving sessions, because a network
	// function that crash-loops over its LI configuration tells every operator that it
	// is LI-provisioned.
	if cfg.NEID == "" {
		return errNoElementIdentifier
	}

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
	// The delivery-failure hook no longer reports. An unreachable mediation function
	// is a condition this element can re-observe — the pool's own accounting answers
	// it — so it has an ending, and TS 103 221-1 clause 5.3 requires an ending to be
	// reported too. A site that announces with nothing that retracts eventually
	// announces something nobody retracts, so both edges belong to whoever can see
	// the transition. The hook nudges that watcher, which keeps the report as prompt
	// as it was while moving the decision to one place.
	var watcher *x1.DestinationWatcher
	pool := x2x3.NewPool(mat.ClientTLS(),
		keepaliveConfig(cfg, reporter),
		func(error) { watcher.Nudge() },
		nil, // drops are covered by the same MDF-unreachable report from the worker
	)
	sub := &subsystem{
		store:     st,
		senderFor: func(addr string) sender { return pool.For(addr) },
		mdf2:      cfg.MDF2,
		iriCtx:    iri.NewContext(),
		neID:      cfg.NEID,
		ids:       x2x3.NewIdentity(cfg.NEID, smfInterceptionPoint),
		reporter:  reporter,
	}
	// Assigned after construction because it reads the subsystem it belongs to: the pool
	// knows what each destination's last delivery established, and only the subsystem knows
	// which destinations the tasking still names.
	sub.unreachable = func() (int, int) { return pool.UnreachableAmong(sub.destinationsInUse()) }
	// The watcher's view of the same destinations, with the identifiers the ADMF
	// provisioned them under. A different shape from the probe's on purpose: the
	// probe answers a status request and takes counts so it *cannot* name a
	// destination, and a destination-scoped report says which. Same fact, two
	// questions.
	if reporter != nil {
		watcher = x1.NewDestinationWatcher(func() []x1.DestinationHealth {
			// x2Destinations, not DeliveryAddresses: it is what delivery resolves, so
			// the configured MDF2 serving a task that named no DID is watched too.
			return x1.DestinationHealthOf(sub.store.Snapshot(), types.DeliveryX2,
				sub.x2Destinations,
				func(addr string) bool { return pool.UnreachableAt(addr) })
		}, reporter, 0)
		go watcher.Watch(nil)
	}
	// Assign the interface only when a reporter exists: a typed-nil would pass the
	// nil check in reportTaskIssue and then panic on use.
	if reporter != nil {
		sub.taskReporter = reporter
	}
	if len(cfg.UPFTriggers) > 0 {
		var triggers *triggerRegistry
		triggers, err = newTriggerRegistry(cfg, mat.ClientTLS(), sub.reportUnattributable)
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

	sub.reportEvent(sc, smfEstablishment(sc))
}

// ReportEstablishmentReject emits an SMFUnsuccessfulProcedure xIRI when the SMF
// refuses a PDU session establishment for a tasked target. cause is the 5GSM
// cause the reject itself carries, so the record and the wire cannot disagree.
//
// A target whose sessions are being refused otherwise produces no record at all,
// and to an agency that silence is indistinguishable from a subject who never
// tried. No-op and silent when LI is inactive or sc is not a target.
func ReportEstablishmentReject(sc *smfctx.SMContext, cause uint8) {
	reportUnsuccessful(sc, iri.SMFFailedPDUSessionEstablishment, cause)
}

// ReportReleaseReject emits an SMFUnsuccessfulProcedure xIRI when the SMF refuses
// a PDU session release for a tasked target. cause is the 5GSM cause the reject
// carries.
func ReportReleaseReject(sc *smfctx.SMContext, cause uint8) {
	reportUnsuccessful(sc, iri.SMFFailedPDUSessionRelease, cause)
}

// reportUnsuccessful is the shared body. It cannot fail the procedure it reports:
// every step is a read, deliverIRI swallows its own errors, and nothing here
// returns to the caller (design D3). That matters more here than elsewhere —
// these hooks sit on paths that are already failing, which is where error
// handling is least exercised.
func reportUnsuccessful(sc *smfctx.SMContext, procedure iri.SMFFailedProcedureType, cause uint8) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	sub.reportEvent(sc, smfUnsuccessful(sc, procedure, cause))
}

// smfUnsuccessful maps a refused procedure to a TS 33.128
// SMFUnsuccessfulProcedure record (XIRIEvent [10]).
//
// initiator is always network: the field says who is "initiating the rejection",
// and on every path SD-Core has, that is the SMF. uE would appear only on a
// PDU SESSION MODIFICATION COMMAND REJECT, which this SMF does not handle.
func smfUnsuccessful(sc *smfctx.SMContext, procedure iri.SMFFailedProcedureType, cause uint8) iri.SMFUnsuccessfulProcedure {
	return iri.SMFUnsuccessfulProcedure{
		FailedProcedureType: procedure,
		FailureCause:        iri.FiveGSMCause(cause),
		Initiator:           iri.InitiatorNetwork,
		SUPI:                supiChoice(sc),
		PEI:                 peiChoice(sc),
		GPSI:                gpsiChoice(sc),
		PDUSessionID:        iri.PDUSessionID(sc.PDUSessionID),
		UEEndpoint:          ueEndpoint(sc),
		DNN:                 iri.DNN(sc.Dnn),
		RequestType:         requestType(sc),
		AccessType:          accessType(sc),
	}
}

// ReportModification emits an SMFPDUSessionModification xIRI for sc if it
// matches an active task. No-op and silent otherwise.
func ReportModification(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	sub.reportEvent(sc, smfModification(sc))
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
	sub.reportEvent(sc, smfRelease(sc))
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

// applyTaskChange is the X1 lifecycle hook (x1.OnTaskChange): one event per
// transition of this element's tasking, carrying the task as it was and as it
// becomes. prev nil is an activation, next nil a removal, both a modification.
func (s *subsystem) applyTaskChange(prev, next *types.InterceptTask) {
	switch {
	case prev == nil:
		s.reportStartOfInterception(*next, nil)
	case next == nil:
		s.reportDeactivation(*prev)
	default:
		s.modifyInterception(*prev, *next)
	}
}

// modifyInterception applies a modification as one reconciliation rather than as
// an activation followed by a deactivation.
//
// A ModifyTask keeps the XID, and everything this element keys off it is the same
// key for both sides: the trigger registry is keyed by the warrant XID, and so is
// the sequence-numbering state. Applying the new task and then tearing down the
// old one let the teardown reclaim the triggers the activation had just installed,
// and let Forget discard numbering the new task's records had already consumed.
// Neither is possible from here, because there is only one pass.
func (s *subsystem) modifyInterception(prev, next types.InterceptTask) {
	wantedCC := prev.WantsProduct(types.ProductCC)
	wantsCC := next.WantsProduct(types.ProductCC)
	if slices.Equal(prev.Targets, next.Targets) && wantedCC == wantsCC {
		// Nothing this POI acts on has moved. It applies interception by target and
		// by product, and the numbering state belongs to the XID, which a
		// modification never changes.
		return
	}

	// Reconcile the triggers held for this warrant against the sessions the task
	// still covers, in one locked pass: a session tasked before and after keeps the
	// trigger it has. Withdrawing everything and reinstalling would stop and restart
	// content interception for a session whose tasking did not change.
	s.retriggerWarrant(next)

	// Duplication re-derives from the task set, which already holds next, so a
	// session reached by either scan is evaluated the same way. Only sessions the
	// old task covered need the extra visit — the new task's own scan covers its.
	if wantedCC {
		s.scanSessions(prev, func(sc *smfctx.SMContext) any {
			if s.applyCC(sc) {
				s.modifySession(sc)
			}

			return nil
		})
	}

	s.reportStartOfInterception(next, &prev)
}

// reportStartOfInterception applies a task to sessions that already exist: emit
// the "start with established PDU session" xIRI (if IRI is wanted) and switch on
// CC duplication (if CC is wanted). It runs on live sessions the target already
// has; sessions established later are handled at establishment by
// ReportEstablishment / ApplyCCTrigger.
//
// already, when set, is the task this one replaces. Interception of a session that
// task already covered did not begin here, so no record says it did — the CC work
// is unaffected, since that re-derives from the task set either way.
func (s *subsystem) reportStartOfInterception(task types.InterceptTask, already *types.InterceptTask) {
	wantIRI := task.WantsProduct(types.ProductIRI)
	s.scanSessions(task, func(sc *smfctx.SMContext) any {
		var event any
		// uEEndpoint is mandatory in this record, and an empty list would assert
		// the session has no endpoint address. A session with no address assigned
		// is not one this record can describe, so report nothing for it rather
		// than something untrue — the CC work below is unaffected either way.
		if wantIRI && ueEndpoint(sc) != nil && !covered(already, sc) {
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

// covered reports whether task already intercepted this session's IRI. Caller
// holds sc.SMLock (sessionTargets reads the session's identity fields).
func covered(task *types.InterceptTask, sc *smfctx.SMContext) bool {
	return task != nil && task.WantsProduct(types.ProductIRI) && sessionTargets(*task, sc)
}

// reportDeactivation undoes the CC duplication a removed warrant caused on the
// target's live sessions. It re-evaluates
// against the remaining task set, so duplication is only cleared once no CC task
// still targets the session (correct under overlapping multi-agency warrants).
// IRI needs no undo, so a pure-IRI deactivation is a no-op.
func (s *subsystem) reportDeactivation(task types.InterceptTask) {
	// Numbering state belongs to the tasking that created it, and a warrant covering
	// many sessions creates a sequence context per session. Done for every warrant,
	// before the CC check below returns early for a pure-IRI one — it is the IRI
	// records that were numbered.
	if s.ids != nil {
		s.ids.Forget(parseXID(task.DeliveryXID()))
	}
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
	// The event these records report is the activation, not whatever each session did
	// earlier, so one instant covers all of them (design D5).
	activated := time.Now()
	go func() {
		for _, sc := range matched {
			sc.SMLock.Lock()
			event := fn(sc)
			corr := correlationOf(sc)   // read under the lock (reads sc.PFCPContext)
			subjectIDs := targetsOf(sc) // likewise: reads the session's identity fields
			sc.SMLock.Unlock()
			if event != nil {
				s.deliverIRI([]types.InterceptTask{task}, corr, subjectIDs, activated, event)
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

// reportEvent delivers event to every task this session's identities match, as the
// session and the clock stood when the event was observed.
//
// The instant is taken here, at the hook, because the X2 Timestamp attribute is the
// time the *event* occurred (TS 33.128 table 5.3.2-2) and not the time a PDU was
// built. Caller holds sc.SMLock: matchingTasks, correlationOf and targetsOf all read
// the session's fields.
func (s *subsystem) reportEvent(sc *smfctx.SMContext, event any) {
	s.deliverIRI(s.matchingTasks(sc), correlationOf(sc), targetsOf(sc), time.Now(), event)
}

// deliverIRI encodes event once and delivers it as an X2 xIRI to every task in
// tasks that wants IRI product. It is silent on any error (encoding or
// delivery) so that interception can never be inferred from SMF behaviour.
func (s *subsystem) deliverIRI(tasks []types.InterceptTask, corr [8]byte, subjectIDs []types.TargetIdentifier, at time.Time, event any) {
	if len(tasks) == 0 {
		return
	}
	if s.ids == nil {
		// An element that cannot say which network function produced a record does not
		// deliver one. Init always supplies this, so reaching here means a subsystem was
		// assembled by hand — fail closed rather than panic, since this runs on a
		// session's own goroutine.
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
		// A provisioned ProductID replaces the task XID in the PDU header
		// (TS 103 221-1 clause 6.2.1.2), so product is labelled with the warrant an
		// ADMF names rather than with the task carrying it.
		xid := parseXID(t.DeliveryXID())
		// The six attributes TS 33.128 table 5.3.2-2 requires, built once per task and
		// carried to every destination it named: the number belongs to the (XID,
		// Correlation ID) context, so two destinations receive one numbering.
		matched, other := t.SplitTargets(subjectIDs)
		// The number is taken here, per record *generated* for this task, and not below
		// per record delivered. That ordering is deliberate twice over: a task resolving
		// to no destination therefore consumes a number nobody receives, which is
		// harmless because nobody is receiving a stream to see a gap in (design D3
		// accepts the same effect for a destination added mid-task); and moving the call
		// inside the destination loop would number each destination separately, which is
		// the per-connection numbering clause 5.3.9 forbids.
		attrs := s.ids.Attributes(xid, corr, at,
			types.XMLFragments(matched), types.XMLFragments(other))
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
				XID:           xid,
				CorrelationID: corr,
				Attributes:    attrs,
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
		GTPTunnelInfo:  gtpTunnelInfo(sc),
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
		GTPTunnelInfo:  gtpTunnelInfo(sc),
	}
}

// smfModification maps an SMContext to a TS 33.128 SMFPDUSessionModification
// record. Only requestType is mandatory.
func smfModification(sc *smfctx.SMContext) iri.SMFPDUSessionModification {
	return iri.SMFPDUSessionModification{
		SUPI:          supiChoice(sc),
		PEI:           peiChoice(sc),
		GPSI:          gpsiChoice(sc),
		SNSSAI:        snssai(sc),
		RequestType:   iri.SMRequestModification,
		AccessType:    accessType(sc),
		PDUSessionID:  iri.PDUSessionID(sc.PDUSessionID),
		GTPTunnelInfo: gtpTunnelInfo(sc),
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
// gtpTunnelInfo carries the session's user plane GTP tunnels. TS 33.128 marks
// gTPTunnelInfo mandatory in the establishment, modification and
// start-of-interception records, and it is the only tunnel field the
// modification record has at all — that record carries no gTPTunnelID.
//
// It reports the same UL NG-U F-TEID as gTPTunnelID, which is what table
// 6.2.3-1C asks for: the F-TEID of the UPF endpoint of the NG-U transport
// bearer. The two fields are not redundant to a mediation function — the
// structured form is where later tunnel detail (additional NG-U bearers, the
// downlink RAN tunnel) is defined to go.
func gtpTunnelInfo(sc *smfctx.SMContext) iri.GTPTunnelInfo {
	return iri.GTPTunnelInfo{
		FiveGSGTPTunnels: iri.FiveGSGTPTunnels{ULNGUUPTunnelInformation: servingUPFTEID(sc)},
	}
}

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
// keepaliveConfig turns the operator's three settings into the clause 6.2.4
// mechanism's configuration.
//
// It encodes no defaults of its own. An unset timer is passed through as zero, which
// x2x3 resolves to the specification's own value — so there is one place where "60
// seconds" is written down, and it is beside the mechanism rather than in each of the
// three network functions that run it.
//
// An unusable setting is reported to the ADMF and then discarded in favour of the
// defaults, rather than refusing to start. The alternatives are both worse: this
// subsystem is optional to the network function, so a refusal here means lawful
// interception silently does not run, and accepting the value as written can mean a
// mechanism that disconnects every delivery connection on a timer. Reporting keeps
// the operator's mistake visible to the only party that can act on it while the
// element keeps intercepting.
func keepaliveConfig(cfg Config, reporter *x1.Reporter) x2x3.KeepaliveConfig {
	ka := x2x3.KeepaliveConfig{
		Disabled: cfg.X2X3KeepaliveEnabled != nil && !*cfg.X2X3KeepaliveEnabled,
	}

	report := func(format string, args ...any) {
		if reporter != nil {
			reporter.Notify(x1.NEIssueInvalidConfig, fmt.Sprintf(format, args...))
		}
	}

	for _, t := range []struct {
		name  string
		value string
		into  *time.Duration
	}{
		{"x2x3KeepaliveTimeP1", cfg.X2X3KeepaliveTimeP1, &ka.TimeP1},
		{"x2x3KeepaliveTimeP2", cfg.X2X3KeepaliveTimeP2, &ka.TimeP2},
	} {
		if t.value == "" {
			continue
		}
		d, err := time.ParseDuration(t.value)
		if err != nil {
			report("%s is not a duration; the specification's default is used instead", t.name)

			continue
		}
		*t.into = d
	}

	if err := ka.Validate(); err != nil {
		report("the configured X2/X3 keepalive timers are unusable and the specification's "+
			"defaults are used instead: %v", err)

		return x2x3.KeepaliveConfig{Disabled: ka.Disabled}
	}

	return ka
}

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
