// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"testing"
	"time"
)

// TestLIKeepaliveTimeoutRefusesWhatItCannotRead: the parse error used to be
// discarded, which read an unusable value as zero — and zero means the fail-safe
// is off. So an operator who asked for the fail-safe and mistyped the duration got
// an element that looked healthy and held tasking nothing would ever reclaim.
//
// Empty stays usable, and that is the distinction: writing nothing states that the
// fail-safe is off, which an operator is entitled to choose. Writing "5min" states
// a window this element cannot read, and treating the two alike is what discarded
// the choice.
func TestLIKeepaliveTimeoutRefusesWhatItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"", 0, true}, // stated: disabled
		{"5m", 5 * time.Minute, true},
		{"90s", 90 * time.Second, true},
		{"5min", 0, false}, // the plausible typo: Go wants "5m"
		{"five minutes", 0, false},
		{"0", 0, true}, // an explicit zero is still a stated choice
	} {
		got, ok := liKeepaliveTimeout(tc.in)
		if ok != tc.ok {
			t.Errorf("liKeepaliveTimeout(%q) ok = %v, want %v", tc.in, ok, tc.ok)

			continue
		}
		if ok && got != tc.want {
			t.Errorf("liKeepaliveTimeout(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
