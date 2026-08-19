// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"time"

	"github.com/omec-project/li/x1"
	smfctx "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/pfcp/lisequence"
	"github.com/wmnsk/go-pfcp/ie"
)

// maxModificationAttempts is how many times an LI modification is sent before the element
// stops trying and reports it.
//
// Bounded because a datapath that refuses is refusing for a reason this element cannot fix,
// and a retry loop against it is a loop with no exit — the same mistake the withdrawal path
// documents for a POI answering "XID not held". Two retries cover a lost datagram and a UPF
// that was mid-restart; past that, what an operator needs is to be told, not for this
// element to keep asking.
const maxModificationAttempts = 3

// modificationSweepInterval is how often the element looks for LI modifications no answer
// arrived for. Short enough that an interception which never started is noticed in the same
// minute, long enough that it costs nothing.
const modificationSweepInterval = 10 * time.Second

// ModificationAnswered is what this element does with the answer to a PFCP modification it
// sent for Lawful Interception.
//
// **The guard that keeps this answer out of the subscriber's procedure is right and stays;
// what it must stop doing is discarding the Cause on the way past.** The element records
// duplication as applied when it sends the modification, so a refusal it never reads leaves
// a task reported as intercepting against a datapath that declined it — and nothing
// re-sends, because the send itself cleared the RULE_UPDATE marker that selects those FARs
// and applyCC will not set it again while the SMF-side Dupl bit already matches the tasking.
//
// answered is false where no Cause could be read or none arrived. That is treated as a
// refusal rather than as an acceptance, and the direction is deliberate: over-applying
// duplication is visible to the CC-POI as content it can attribute, while under-applying it
// is silent — so the ambiguous case resolves toward retry.
//
// Called from the PFCP response handlers, which do not hold the session lock at this point.
func ModificationAnswered(req lisequence.Request, cause uint8, answered bool) {
	sub := active.Load()
	if sub == nil {
		return
	}
	if answered && cause == ie.CauseRequestAccepted {
		sub.modificationApplied(req)

		return
	}
	sub.modificationNotApplied(req)
}

// modKey names one session's LI modification at one UPF, which is what an attempt count
// belongs to: a session may be duplicated at several UPFs, and one refusing says nothing
// about the others.
type modKey struct {
	seid   uint64
	nodeID string
}

// modificationApplied forgets the attempts made for a modification the datapath took.
func (s *subsystem) modificationApplied(req lisequence.Request) {
	s.modMu.Lock()
	defer s.modMu.Unlock()

	delete(s.modAttempts, modKey{seid: req.SEID, nodeID: req.NodeID})
}

// attemptsFor records another attempt at this modification and reports how many have now
// been made.
func (s *subsystem) attemptsFor(req lisequence.Request) int {
	s.modMu.Lock()
	defer s.modMu.Unlock()

	if s.modAttempts == nil {
		s.modAttempts = map[modKey]int{}
	}
	k := modKey{seid: req.SEID, nodeID: req.NodeID}
	s.modAttempts[k]++

	return s.modAttempts[k]
}

// giveUpOn stops counting attempts for a modification this element will not retry again.
func (s *subsystem) giveUpOn(req lisequence.Request) {
	s.modMu.Lock()
	defer s.modMu.Unlock()

	delete(s.modAttempts, modKey{seid: req.SEID, nodeID: req.NodeID})
}

// modificationNotApplied retries an LI modification the datapath did not apply, or reports
// it where retrying is no longer the right answer.
func (s *subsystem) modificationNotApplied(req lisequence.Request) {
	if s.attemptsFor(req) >= maxModificationAttempts {
		s.giveUpOn(req)

		// Named at element scope and countable, carrying no target and no warrant. Which
		// interception this was is the ADMF's to work out from its own provisioning, and
		// this element may not put a warrant on this channel to say it.
		//
		// The two directions are separate facts and are reported as such: an activation
		// that did not take is an interception that is not running, and a withdrawal that
		// did not take is content still being duplicated under authority that has gone.
		if req.Duplicating {
			s.reporter.NotifyAsync(x1.NEIssueDuplicationRefused,
				"the user plane did not apply a duplication this element has acknowledged; "+
					"content interception is not running for a session it covers")

			return
		}
		s.reporter.NotifyAsync(x1.NEIssueDuplicationRefused,
			"the user plane did not apply the removal of a duplication this element has "+
				"withdrawn; a session may still be duplicated under authority that has gone")

		return
	}

	sc := smfctx.GetSMContextBySEID(req.SEID)
	if sc == nil {
		// The session went while the answer was in flight. Nothing is left to duplicate,
		// so the refused modification has nothing to apply to.
		return
	}

	sc.SMLock.Lock()
	defer sc.SMLock.Unlock()

	if sc.Tunnel == nil {
		// The session is being released. Its duplication goes with it.
		return
	}

	// **Re-establish the marker the send cleared.** BuildPfcpSessionModificationRequest
	// sets far.State = RULE_CREATE for every FAR it encodes, so by the time this runs the
	// RULE_UPDATE that ModifySessionForLI selects on is gone — and re-deriving finds
	// nothing to do, because the SMF-side Dupl bit already equals what the tasking implies.
	// Marking them here is what makes the re-send carry anything at all.
	//
	// Only the FARs the send left in RULE_CREATE: one still marked RULE_UPDATE belongs to a
	// modification the session's own path has not sent yet, and re-sending it here would
	// take it out from under that path.
	marked := 0
	forEachForwardingFAR(sc, func(far *smfctx.FAR) {
		if far.State == smfctx.RULE_CREATE {
			far.State = smfctx.RULE_UPDATE
			marked++
		}
	})
	if marked == 0 {
		return
	}

	// Under the session lock, as every other caller of this sends: the modifier reads the
	// session's data-path pool and its PFCP context.
	s.modifySession(sc)
}

// watchModifications sweeps the modifications no answer arrived for, and treats each as not
// applied.
//
// Silence is not a lesser case than a refusal: a refusal says the datapath declined, while
// silence says this element does not know — and it recorded the duplication as applied
// before it sent. So the two reach the same handling.
//
// It returns when stop is closed; production passes nil, because the condition can arise for
// as long as this element can send a modification.
func (s *subsystem) watchModifications(stop <-chan struct{}) {
	ticker := time.NewTicker(modificationSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, req := range lisequence.Expired() {
				s.modificationNotApplied(req)
			}
		case <-stop:
			return
		}
	}
}
