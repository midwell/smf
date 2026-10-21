// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/transaction"
)

// liFailures records the failure hooks, alongside the teardown pair captureLI records.
type liFailures struct {
	*liCalls
	establishmentRejects []uint8
	modificationRejects  int
}

func captureLIFailures(t *testing.T) *liFailures {
	t.Helper()
	c := &liFailures{liCalls: captureLI(t)}
	establishment, modification := liReportEstablishmentReject, liReportModificationReject
	liReportEstablishmentReject = func(_ *smf_context.SMContext, cause uint8) {
		c.establishmentRejects = append(c.establishmentRejects, cause)
	}
	liReportModificationReject = func(*smf_context.SMContext, uint8) { c.modificationRejects++ }
	t.Cleanup(func() { liReportEstablishmentReject, liReportModificationReject = establishment, modification })

	return c
}

// A create that failed before its establishment was reported -- the UPF refused it, never answered,
// or the anchor was among those that did not accept -- is reported as a failed establishment, with
// the cause the reject to the UE carries. Its triggers are withdrawn as well: a UPF that accepted
// while another refused was triggered, and the context removed next is the last thing that could
// withdraw them.
func TestAFailedEstablishmentNeverReportedIsReportedAsFailed(t *testing.T) {
	calls := captureLIFailures(t)
	sc := teardownSession(t)
	t.Cleanup(func() { smf_context.RemoveSMContext(sc.Ref) })

	ReportEstablishmentFailure(sc)

	if len(calls.establishmentRejects) != 1 {
		t.Fatalf("failed-establishment records = %d, want 1: a tasked subject whose session failed at "+
			"the user plane otherwise leaves the agency the silence it also sees for a subject who never tried",
			len(calls.establishmentRejects))
	}
	if got := calls.establishmentRejects[0]; got != nasMessage.Cause5GSMRequestRejectedUnspecified {
		t.Errorf("record cause = %d, want %d, the cause the reject to the UE carries",
			got, nasMessage.Cause5GSMRequestRejectedUnspecified)
	}
	if calls.untasked != 1 {
		t.Errorf("triggers withdrawn %d times, want 1", calls.untasked)
	}
	if calls.released != 0 {
		t.Errorf("release reported %d times for a session whose establishment was never reported", calls.released)
	}
}

// A create can fail after its establishment was reported: the record goes out when the anchor UPF
// accepts, and another UPF's refusal fails the whole create afterwards. The agency then holds an
// establishment record, so the session is reported released -- what happened to it -- rather than
// as a failed establishment beside the one it already holds. And the trigger installed at the
// anchor is withdrawn.
func TestAFailedEstablishmentAlreadyReportedIsReportedReleased(t *testing.T) {
	calls := captureLIFailures(t)
	sc := teardownSession(t)
	t.Cleanup(func() { smf_context.RemoveSMContext(sc.Ref) })
	sc.LiEstablishmentReported = true

	ReportEstablishmentFailure(sc)

	if calls.released != 1 || calls.untasked != 1 {
		t.Errorf("release reported %d times and triggers withdrawn %d, want 1 and 1: the agency holds "+
			"an establishment record and the anchor holds a trigger for a session that no longer exists",
			calls.released, calls.untasked)
	}
	if len(calls.establishmentRejects) != 0 {
		t.Errorf("failed-establishment records = %d after an establishment record, want 0: the agency "+
			"would hold both", len(calls.establishmentRejects))
	}
}

// A modification the UE's update asked for, which the user plane refused or never answered, is
// reported failed exactly once: the counterpart to the modification record emitted before the send.
func TestAFailedUeModificationIsReportedFailedOnce(t *testing.T) {
	for _, verdict := range failedModificationVerdicts {
		t.Run(verdict.String(), func(t *testing.T) {
			calls := captureLIFailures(t)
			smContext := sessionTheUserPlaneAnswers(t, verdict)

			request := models.UpdateSmContextRequest{}
			data := models.NewSmContextUpdateData()
			data.SetUpCnxState(models.UPCNXSTATE_DEACTIVATED)
			request.SetJsonData(*data)

			txn := &transaction.Transaction{Req: request, Ctxt: smContext}
			awaitHandler(t, func() {
				if err := HandlePDUSessionSMContextUpdate(txn); err != nil {
					t.Errorf("the update was not answered: %v", err)
				}
			})

			if len(smContext.SBIPFCPCommunicationChan) != 0 {
				t.Fatal("the answer was never read: the test did not reach the path it is about")
			}
			if calls.modificationRejects != 1 {
				t.Errorf("failed-modification records = %d, want 1: the agency otherwise holds a record "+
					"asserting a modification that never took effect", calls.modificationRejects)
			}
		})
	}
}

// One the user plane applied draws no failure record.
func TestAnAppliedUeModificationIsNotReportedFailed(t *testing.T) {
	calls := captureLIFailures(t)
	smContext := sessionTheUserPlaneAnswers(t, smf_context.SessionUpdateSuccess)

	request := models.UpdateSmContextRequest{}
	data := models.NewSmContextUpdateData()
	data.SetUpCnxState(models.UPCNXSTATE_DEACTIVATED)
	request.SetJsonData(*data)

	txn := &transaction.Transaction{Req: request, Ctxt: smContext}
	awaitHandler(t, func() {
		if err := HandlePDUSessionSMContextUpdate(txn); err != nil {
			t.Errorf("the update was not answered: %v", err)
		}
	})

	if calls.modificationRejects != 0 {
		t.Errorf("failed-modification records = %d for a modification the user plane applied", calls.modificationRejects)
	}
}

// A failed modification that no modification record preceded draws no failure record either. A
// policy update reports none before its send, so a failure record for it would be the counterpart
// of nothing -- the shape the hook had in the PFCP send-error handler, which every unanswered
// modification reached: this element's own interception updates and restoration's rule reissues
// among them.
func TestAFailedPolicyUpdateIsNotReportedAsAFailedModification(t *testing.T) {
	for _, verdict := range failedModificationVerdicts {
		t.Run(verdict.String(), func(t *testing.T) {
			calls := captureLIFailures(t)
			smContext := sessionTheUserPlaneAnswers(t, verdict)
			sendModificationRequest = func(smf_context.NodeID, *smf_context.SMContext, []*smf_context.PDR, []*smf_context.FAR,
				[]*smf_context.BAR, []*smf_context.QER, []*smf_context.PDR, []*smf_context.FAR, []*smf_context.QER, uint16,
			) error {
				smContext.PendingUPF["127.0.0.1"] = true
				return nil
			}

			txn := &transaction.Transaction{Req: models.SmPolicyNotification{}, Ctxt: smContext}
			awaitHandler(t, func() {
				if err := HandleSMPolicyUpdateNotify(txn); err == nil {
					t.Error("a policy update the user plane did not apply was reported as applied")
				}
			})

			if len(smContext.SBIPFCPCommunicationChan) != 0 {
				t.Fatal("the answer was never read: the test did not reach the path it is about")
			}
			if calls.modificationRejects != 0 {
				t.Errorf("failed-modification records = %d for a policy update no modification record preceded",
					calls.modificationRejects)
			}
		})
	}
}
