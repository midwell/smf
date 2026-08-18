// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package lisequence records which PFCP sequence numbers belong to modifications
// this element sent for Lawful Interception, so their responses can be recognised
// and kept out of the session's own procedure handling.
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

// sequences records the sequence numbers of PFCP modifications sent for Lawful
// Interception.
//
// Bounded on purpose. Entries are normally consumed by the response they describe,
// but a response that never arrives — a lost datagram, a UPF that restarts — would
// otherwise leave one behind forever, and an unbounded map that grows with traffic
// while nothing prunes it is a fault this project has already had to fix once.
// Each insert drops anything older than the window, so what is held is bounded by
// the rate of LI modifications rather than by uptime.
var (
	sequences = map[uint32]time.Time{}
	lock      sync.Mutex
	maxAge    = 2 * time.Minute
)

// Mark records that seqNum belongs to an LI-initiated modification.
func Mark(seqNum uint32) {
	lock.Lock()
	defer lock.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for seq, at := range sequences {
		if at.Before(cutoff) {
			delete(sequences, seq)
		}
	}
	sequences[seqNum] = time.Now()
}

// Is reports whether seqNum was an LI-initiated modification, consuming the record.
// A response arrives once, so holding the entry past it would only keep a sequence
// number that the counter will eventually reuse.
func Is(seqNum uint32) bool {
	lock.Lock()
	defer lock.Unlock()

	if _, ok := sequences[seqNum]; !ok {
		return false
	}
	delete(sequences, seqNum)

	return true
}
