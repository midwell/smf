// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package lisequence records the PFCP modifications this element sent for Lawful
// Interception, so their responses can be recognised, kept out of the session's own
// procedure handling, and — the part that was missing — acted on.
//
// It is its own package because both response handlers need it and they cannot both
// reach it anywhere else: pfcp/message calls pfcp/adapter, so the adapter cannot
// import pfcp/message, which is where this used to live. The guard has to be in the
// handler rather than at one call site — an LI response reaching subscriber procedure
// handling is the fault, whichever path delivered it — so the record moves to where
// every handler can ask.
package lisequence

import (
	"sync"
	"time"
)

// Request is what an LI-initiated modification asked for, carried alongside its
// sequence number so the answer can be correlated with it.
//
// **The state has to travel, because it cannot be re-derived when the answer arrives.**
// BuildPfcpSessionModificationRequest sets `far.State = RULE_CREATE` for every FAR it
// encodes, so the `RULE_UPDATE` marker that selected these FARs is cleared by the send
// itself — and `applyCC` will not set it again, because the SMF-side `Dupl` bit already
// equals what the tasking implies. A response handler that went back to the session to
// work out what had been asked would therefore find nothing to do, which is why a
// refused activation was never retried.
type Request struct {
	// SEID is the local PFCP session identifier the modification was sent for, which is
	// how the session is found again.
	SEID uint64
	// NodeID is the UPF it went to, as the session keys its PFCP context.
	NodeID string
	// Duplicating is what the datapath was asked to do with the session's forwarding
	// FARs: true to start duplicating, false to stop. Held because the two failures are
	// not the same condition — a refused activation is an interception that is not
	// running, and a refused withdrawal is one that has not stopped.
	Duplicating bool
}

// pending records the LI modifications awaiting an answer.
//
// Bounded on purpose. Entries are normally consumed by the response they describe, but a
// response that never arrives — a lost datagram, a UPF that restarts — would otherwise
// leave one behind forever, and an unbounded map that grows with traffic while nothing
// prunes it is a fault this project has already had to fix once. Expired records the
// interception subsystem to sweep; Mark drops anything far past the window as the backstop
// for a deployment where nothing sweeps.
var (
	pending = map[uint32]entry{}
	lock    sync.Mutex
	// maxAge is how long an answer may take before the modification counts as unanswered.
	// Comfortably longer than a UPF's own response time and far shorter than the interval
	// at which an operator would notice interception missing.
	maxAge = 30 * time.Second
	// now is the clock, held here so a test can move it rather than wait.
	now = time.Now
)

type entry struct {
	req  Request
	sent time.Time
}

// Mark records that seqNum belongs to an LI-initiated modification, and what it asked for.
func Mark(seqNum uint32, req Request) {
	lock.Lock()
	defer lock.Unlock()

	// The backstop: entries far past the window belong to a deployment where nothing is
	// sweeping, and they may not accumulate.
	cutoff := now().Add(-4 * maxAge)
	for seq, e := range pending {
		if e.sent.Before(cutoff) {
			delete(pending, seq)
		}
	}
	pending[seqNum] = entry{req: req, sent: now()}
}

// Take reports whether seqNum was an LI-initiated modification and what it asked for,
// consuming the record. A response arrives once, so holding the entry past it would only
// keep a sequence number that the counter will eventually reuse.
func Take(seqNum uint32) (Request, bool) {
	lock.Lock()
	defer lock.Unlock()

	e, ok := pending[seqNum]
	if !ok {
		return Request{}, false
	}
	delete(pending, seqNum)

	return e.req, true
}

// Expired removes and returns the modifications no answer has arrived for within the
// window.
//
// An unanswered modification is not a lesser case than a refused one. A refusal says the
// datapath declined; silence says the element does not know, and the element must treat
// "do not know" as "not applied" — over-applying duplication is visible to the CC-POI as
// content it can attribute, while under-applying it is silent, which is why the ambiguous
// case resolves toward retry.
func Expired() []Request {
	lock.Lock()
	defer lock.Unlock()

	cutoff := now().Add(-maxAge)

	var out []Request
	for seq, e := range pending {
		if e.sent.Before(cutoff) {
			out = append(out, e.req)
			delete(pending, seq)
		}
	}

	return out
}
