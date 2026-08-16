// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package service

import "time"

// liKeepaliveTimeout reads the configured Lawful Interception fail-safe window.
// It reports false for a value this element cannot read.
//
// Empty is not such a value: an operator who writes nothing has stated that the
// fail-safe is off, and that choice is honoured. A value that does not parse is a
// choice this element could not read, and the difference matters because reading
// it as zero — which is what discarding the parse error did — turns a mistyped
// duration into a silently disabled fail-safe on an element that otherwise looks
// healthy, holding tasking nothing will ever reclaim.
//
// Split out from Start so it can be tested. Start does not return an error and
// must not crash-loop over LI configuration — that would tell every operator this
// element is LI-provisioned — so the refusal there is to leave LI unstarted, and
// that whole function is not reachable from a test.
func liKeepaliveTimeout(v string) (time.Duration, bool) {
	if v == "" {
		return 0, true
	}

	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, false
	}

	return d, true
}
