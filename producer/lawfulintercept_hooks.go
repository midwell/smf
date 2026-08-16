// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	smf_context "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/lawfulintercept"
)

// The Lawful Interception teardown hooks, reached through package variables so
// that a test can observe which paths call them.
//
// A test cannot do that by activating the subsystem: `active` is package-private
// to lawfulintercept, and Init needs mTLS material and a TCP bind that this
// package's tests have no business standing up. Without a seam the hooks are
// silent no-ops in every test, so a path that stopped calling them would look
// exactly like a path that calls them — which is how two teardown paths came to
// be missing them for as long as they were.
//
// The seam lives here rather than as test-only API on lawfulintercept, because
// what needs asserting is which of *this* package's paths call the hooks, not
// anything about the subsystem behind them.
//
// Production behaviour is unchanged: these are the same two functions, and both
// remain silent no-ops when LI is not configured.
var (
	liReportRelease = lawfulintercept.ReportRelease
	liUntriggerCC   = lawfulintercept.UntriggerCC
)

// reportAndUntask ends a session's interception state: the release record for the
// mediation function, and the withdrawal of the triggers that session held.
//
// The two always travel together — a teardown that reports without withdrawing
// leaves the trigger installed, and this element keeps a POI alive while it
// believes that POI holds tasking it installed, so the keepalives that trigger
// earns are what stop the POI's fail-safe from ever reclaiming it. Naming the
// pair once makes a teardown path that calls only one of them visible as an
// omission rather than a plausible line of code.
//
// Caller holds smContext.SMLock.
func reportAndUntask(smContext *smf_context.SMContext) {
	liReportRelease(smContext)
	liUntriggerCC(smContext)
}
