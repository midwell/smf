// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"testing"

	"github.com/omec-project/li/types"
	smfctx "github.com/omec-project/smf/context"
)

// TestARetargetMidScanStopsDeliveringForThePreviousSubject is the subject half of
// "product is delivered only under authority that still names the subject".
//
// The scan re-reads the task before every record, which establishes that the warrant still
// exists and — since the record is built from what the store now holds — which products it
// wants and where its product goes. It did not establish that the warrant still names *this*
// subject. So a ModifyTask that retargets a warrant mid-scan left the remaining sessions
// producing records about the previous subject, delivered under the warrant's own identifier
// to the new subject's agency: well-formed, correctly attributed, and about somebody the
// warrant no longer covers.
//
// Driven through the deterministic seam rather than by racing an X1 request against the
// scan: the window between one record and the next is a few instructions wide.
func TestARetargetMidScanStopsDeliveringForThePreviousSubject(t *testing.T) {
	const (
		subject    = "262019876543210"
		retargeted = "262010000000001"
	)

	task := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: subject}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}

	// Three sessions of the one subject, so there are records after the first.
	sub, st, snd := scanFixture(t, task, 3)

	// Between the first record and the second, the ADMF retargets the warrant. From that
	// point the task names a different subject, and every remaining session belongs to the
	// previous one.
	retarget := task
	retarget.Targets = []types.TargetIdentifier{{Type: types.TargetSUPI, Value: retargeted}}

	beforeScanRecord = func() {
		// Activate over a held XID is how a modification reaches the store — the same
		// path x1's ModifyTask takes.
		if !st.Activate(retarget) {
			t.Error("re-activating the retargeted task failed")
		}
		// Once: the remaining sessions must all be refused, not just the next one.
		beforeScanRecord = nil
	}
	t.Cleanup(func() { beforeScanRecord = nil })

	sub.reportStartOfInterception(task, nil)
	sub.scans.Wait()

	// At most the one record that went out before the retarget. Anything more is a record
	// about the previous subject delivered under a warrant that has been retargeted.
	if n := snd.count(); n > 1 {
		t.Errorf("the scan delivered %d records for a subject the warrant no longer names, want at "+
			"most 1 (the one already in flight when it was retargeted): each is a well-formed "+
			"record about the wrong person, sent to the new subject's agency under the warrant's "+
			"own identifier", n)
	}
}

// TestAScanStillDeliversWhileTheSubjectIsNamed keeps the check from becoming a scan that
// delivers nothing: a warrant whose targets do not move produces a record for every session
// it covers.
func TestAScanStillDeliversWhileTheSubjectIsNamed(t *testing.T) {
	task := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}

	sub, _, snd := scanFixture(t, task, 3)

	sub.reportStartOfInterception(task, nil)
	sub.scans.Wait()

	if n := snd.count(); n != 3 {
		t.Errorf("the scan delivered %d records for three covered sessions, want 3", n)
	}
}

// TestADeactivationScanIsNotSubjectChecked is the exemption, and it is the one that would
// otherwise reintroduce the defect this whole rule is about.
//
// A deactivation scan runs *because* the task was removed, and its job is to take
// duplication down. Testing the subject against a task the store no longer holds — or
// against the task as it stood after a retarget — would leave the datapath duplicating for
// a warrant that no longer exists: interception outliving its authority, reached by applying
// the authority rule to the path that enforces it.
func TestADeactivationScanIsNotSubjectChecked(t *testing.T) {
	task := types.InterceptTask{
		XID:      "11111111-1111-4111-8111-111111111111",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}},
		Products: []types.ProductType{types.ProductCC},
		State:    types.TaskActive,
	}

	sub, st, _ := scanFixture(t, task, 2)

	type owned struct {
		sc  *smfctx.SMContext
		far *smfctx.FAR
	}
	var duplicating []owned
	smfctx.RangeSMContexts(func(sc *smfctx.SMContext) bool {
		sc.SMLock.Lock()
		forEachForwardingFAR(sc, func(far *smfctx.FAR) {
			setDuplication(far, true)
			duplicating = append(duplicating, owned{sc: sc, far: far})
		})
		sc.SMLock.Unlock()

		return true
	})
	if len(duplicating) == 0 {
		t.Fatal("no forwarding FAR to duplicate on; this test would assert nothing")
	}

	// The warrant is withdrawn, which is what causes the deactivation scan.
	if !st.Deactivate(task.XID) {
		t.Fatal("Deactivate failed")
	}
	sub.reportDeactivation(task)
	sub.scans.Wait()

	for _, d := range duplicating {
		d.sc.SMLock.Lock()
		on := d.far.ApplyAction.Dupl
		d.sc.SMLock.Unlock()
		if on {
			t.Error("duplication is still set after the warrant was withdrawn: the subject check " +
				"was applied to the path whose job is to stop interception, so the datapath goes " +
				"on copying a subject's traffic under authority that has been taken away")
		}
	}
}
