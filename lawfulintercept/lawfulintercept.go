// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package lawfulintercept is the SMF's Lawful Interception IRI-POI. It receives
// interception tasks over X1 (mutual TLS), matches PDU-session events against
// tasked targets, and delivers the resulting xIRI to an MDF2 over X2. It is
// opt-in: inactive — and silent — unless the SMF is started with LI credentials,
// so an SMF that is not intercepting behaves and looks exactly as before.
package lawfulintercept

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
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

	AdmfURL          string        // ADMF X1 endpoint for NE-initiated issue reports (empty = disabled)
	AdmfID           string        // the responsible ADMF's identifier (for reports)
	KeepaliveTimeout time.Duration // purge tasking if no X1 message within this (0 = disabled)
}

// sender delivers an xIRI/xCC PDU to an MDF. *x2x3.Client satisfies it; tests
// inject a capturing implementation to assert per-warrant delivery isolation.
type sender interface {
	Send(*x2x3.PDU) error
}

type subsystem struct {
	store    *store.Store
	client   sender
	iriCtx   *liasn1.Context
	neID     string
	reporter *x1.Reporter // nil when NE-initiated reporting is not configured
}

// active holds the running subsystem, or nil when LI is not configured.
var active atomic.Pointer[subsystem]

// Init starts the SMF LI IRI-POI: it loads the LI credentials, opens the X1
// listener (mutual TLS), and prepares X2 delivery to the MDF2. Call it once at
// SMF startup, only when LI is configured.
func Init(cfg Config) error {
	mat, err := mtls.Load(cfg.Cert, cfg.Key, cfg.CACert)
	if err != nil {
		return err
	}
	st := store.New()
	sub := &subsystem{
		store:  st,
		client: x2x3.NewClient(cfg.MDF2, mat.ClientTLS()),
		iriCtx: iri.NewContext(),
		neID:   cfg.NEID,
	}
	if cfg.AdmfURL != "" {
		sub.reporter = x1.NewReporter(cfg.AdmfURL, cfg.AdmfID, cfg.NEID, mat.ClientTLS())
	}
	// OnActivate/OnDeactivate scan already-established sessions when a warrant is
	// (de)tasked mid-session (tasks 4.7/4.8): emit the "start with established PDU
	// session" xIRI and (de)activate CC duplication on live sessions.
	x1srv := x1.NewServer(st, cfg.NEID,
		x1.OnActivate(sub.reportStartOfInterception),
		x1.OnDeactivate(sub.reportDeactivation))
	// Bind the X1 listener synchronously so a bind/permission failure is reported
	// to the caller, rather than being swallowed in a goroutine while LI already
	// looks enabled (active.Store below) — otherwise no X1 tasking can be received.
	ln, err := net.Listen("tcp", cfg.X1Listen)
	if err != nil {
		if sub.reporter != nil {
			_ = sub.reporter.ReportNEIssue(x1.NEIssueX1ListenFailed, "X1 listener bind failed")
		}
		return fmt.Errorf("lawful interception: X1 listen on %s: %w", cfg.X1Listen, err)
	}
	srv := &http.Server{Handler: x1srv, TLSConfig: mat.ServerTLS()}
	// Certificates come from TLSConfig, so the file arguments are empty.
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	// Keepalive fail-safe: purge tasking if the ADMF goes silent (TS 103 221-1).
	if cfg.KeepaliveTimeout > 0 {
		go x1srv.WatchKeepalive(cfg.KeepaliveTimeout)
	}
	active.Store(sub)
	return nil
}

// ReportEstablishment emits an SMFPDUSessionEstablishment xIRI for sc if it
// matches an active task. No-op and silent when LI is inactive or sc is not a
// target.
func ReportEstablishment(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	sub.deliverIRI(sub.matchingTasks(sc), smfEstablishment(sc))
}

// ReportModification emits an SMFPDUSessionModification xIRI for sc if it
// matches an active task. No-op and silent otherwise.
func ReportModification(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	sub.deliverIRI(sub.matchingTasks(sc), smfModification(sc))
}

// ReportRelease emits an SMFPDUSessionRelease xIRI for sc if it matches an
// active task. No-op and silent otherwise.
func ReportRelease(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil {
		return
	}
	sub.deliverIRI(sub.matchingTasks(sc), smfRelease(sc))
}

// ApplyCCTrigger is the SMF Content-of-Communication Triggering Function. When
// the session's target has an active task requesting CC product, it marks the
// session's forwarding FARs for user-plane duplication (ApplyAction DUPL +
// Duplicating Parameters to the LI Function) so the serving UPF(s) tee the
// traffic to the MDF3. No-op and silent when LI is inactive.
//
// It walks the session's whole data-path pool, so duplication is applied on
// every UPF serving the target (multi-slice / UPF scaling), covering task 4.6.
//
// SCOPE: this runs from SendPFCPRules at PDU-session establishment, so it triggers
// CC for sessions established after tasking. The complementary case — a warrant
// (de)tasked while the session is already up — is handled by the X1
// OnActivate/OnDeactivate hooks (reportStartOfInterception / reportDeactivation),
// which re-evaluate CC and re-send a PFCP modification (tasks 4.7/4.8).
func ApplyCCTrigger(sc *smfctx.SMContext) {
	sub := active.Load()
	if sub == nil || sc == nil || sc.Tunnel == nil {
		return
	}
	cc := sub.ccTasked(sc)
	forEachForwardingFAR(sc, func(far *smfctx.FAR) { setDuplication(far, cc) })
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
		if wantIRI {
			event = smfStartOfInterception(sc)
		}
		if s.applyCC(sc) {
			s.modifySession(sc)
		}
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
			sc.SMLock.Unlock()
			if event != nil {
				s.deliverIRI([]types.InterceptTask{task}, event)
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
		_ = sessionModifier(sc)
	}
}

// sessionTargets reports whether task's target identifier matches one of sc's
// identifiers. Caller holds sc.SMLock (targetsOf reads sc's identity fields).
func sessionTargets(task types.InterceptTask, sc *smfctx.SMContext) bool {
	return slices.Contains(targetsOf(sc), task.Target)
}

// deliverIRI encodes event once and delivers it as an X2 xIRI to every task in
// tasks that wants IRI product. It is silent on any error (encoding or
// delivery) so that interception can never be inferred from SMF behaviour.
func (s *subsystem) deliverIRI(tasks []types.InterceptTask, event any) {
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
		if err := s.client.Send(&x2x3.PDU{
			Type:          x2x3.PDUTypeX2,
			PayloadFormat: x2x3.PayloadFormat3GPP33128,
			Direction:     x2x3.DirectionNotApplicable,
			XID:           parseXID(t.XID),
			Payload:       payload,
		}); err != nil && s.reporter != nil {
			// MDF delivery failed — surface to the ADMF over X1 (throttled,
			// NE-level, no target id), never to general logs.
			_ = s.reporter.ReportNEIssue(x1.NEIssueMDFUnreachable, "MDF2 X2 delivery failed")
		}
	}
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
		DNN:            iri.DNN(sc.Dnn),
		RequestType:    iri.SMRequestInitial,
		AccessType:     iri.AccessThreeGPP,
	}
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
		DNN:            iri.DNN(sc.Dnn),
		RequestType:    iri.SMRequestExisting,
		AccessType:     iri.AccessThreeGPP,
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
		AccessType:   iri.AccessThreeGPP,
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

// parseXID converts an X1 task id (a UUID string) to the 16-byte XID carried in
// the X2 PDU header. On any parse failure it returns the zero XID (best-effort).
func parseXID(xid types.XID) [16]byte {
	var out [16]byte
	b, err := hex.DecodeString(strings.ReplaceAll(string(xid), "-", ""))
	if err == nil && len(b) == len(out) {
		copy(out[:], b)
	}
	return out
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
