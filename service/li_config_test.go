// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"testing"

	"github.com/omec-project/smf/factory"
)

// TestTheKeepaliveSettingsReachTheInterceptionSubsystem: every keepalive key an operator can set
// in the li block must reach lawfulintercept.Config. One dropped in the mapping is accepted by the
// strict decode and then silently ignored — an operator who agreed "no keepalives" with the agency
// gets the default procedure deactivating tasking anyway.
func TestTheKeepaliveSettingsReachTheInterceptionSubsystem(t *testing.T) {
	cfg := liConfig(&factory.Li{
		KeepaliveTimeout:       "2h",
		KeepaliveTimeP1:        "2m",
		KeepaliveTimeP3:        "3h",
		KeepaliveRetainTasking: true,
		KeepaliveDisabled:      true,
	}, nil)

	if cfg.KeepaliveTimeout != "2h" || cfg.KeepaliveTimeP1 != "2m" || cfg.KeepaliveTimeP3 != "3h" {
		t.Errorf("timers not carried: %q %q %q", cfg.KeepaliveTimeout, cfg.KeepaliveTimeP1, cfg.KeepaliveTimeP3)
	}
	if !cfg.KeepaliveRetainTasking {
		t.Error("keepaliveRetainTasking was dropped")
	}
	if !cfg.KeepaliveDisabled {
		t.Error("keepaliveDisabled was dropped")
	}
}
