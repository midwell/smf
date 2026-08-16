// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
)

// liCalls records which teardown hooks ran, by swapping the package seam.
type liCalls struct{ released, untasked int }

func captureLI(t *testing.T) *liCalls {
	t.Helper()
	c := &liCalls{}
	release, untrigger := liReportRelease, liUntriggerCC
	liReportRelease = func(*smf_context.SMContext) { c.released++ }
	liUntriggerCC = func(*smf_context.SMContext) { c.untasked++ }
	t.Cleanup(func() { liReportRelease, liUntriggerCC = release, untrigger })

	return c
}

// teardownSession builds a session in the global pool, since the teardown paths
// reach it through that.
func teardownSession(t *testing.T) *smf_context.SMContext {
	t.Helper()
	if factory.SmfConfig.Configuration == nil {
		off := false
		factory.SmfConfig.Configuration = &factory.Configuration{
			KafkaInfo: factory.KafkaInfo{EnableKafka: &off},
		}
		t.Cleanup(func() { factory.SmfConfig.Configuration = nil })
	}
	sc := smf_context.NewSMContext("imsi-262019876543210", 5)
	sc.Supi = "imsi-262019876543210"

	return sc
}

// TestContextReplacementReportsAndUntasks is the assertion that was impossible
// before the seam, and the one whose absence let this path ship without the
// hooks: a session torn down because a newer context replaced it must still emit
// its release and give up its triggers.
//
// The hooks are silent no-ops unless LI is configured, so without a seam a path
// that never calls them is indistinguishable from one that does.
func TestContextReplacementReportsAndUntasks(t *testing.T) {
	calls := captureLI(t)
	sc := teardownSession(t)

	if err := HandlePduSessionContextReplacement(sc.Ref); err != nil {
		t.Fatalf("HandlePduSessionContextReplacement: %v", err)
	}

	if calls.released != 1 {
		t.Errorf("release reported %d times, want 1 — an agency cannot tell a session "+
			"that ended from a subject who went quiet", calls.released)
	}
	if calls.untasked != 1 {
		t.Errorf("triggers withdrawn %d times, want 1 — a trigger left installed keeps "+
			"this element's keepalives flowing, which is what stops the POI's fail-safe "+
			"from reclaiming it", calls.untasked)
	}
}

// TestTeardownHooksTravelTogether pins the pairing itself. Reporting without
// withdrawing is the more damaging half-measure, because the record makes the
// teardown look handled while the trigger stays installed.
func TestTeardownHooksTravelTogether(t *testing.T) {
	calls := captureLI(t)
	sc := teardownSession(t)
	t.Cleanup(func() { smf_context.RemoveSMContext(sc.Ref) })

	reportAndUntask(sc)

	if calls.released != calls.untasked {
		t.Errorf("release reported %d times but triggers withdrawn %d — the two must not "+
			"come apart", calls.released, calls.untasked)
	}
}
