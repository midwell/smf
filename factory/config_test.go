// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"testing"

	"go.yaml.in/yaml/v4"
)

const (
	GNB = "gnb"
)

func TestKafkaEnabledByDefault(t *testing.T) {
	err := InitConfigFactory("../config/smfcfg.yaml")
	if err != nil {
		t.Errorf("Could not load default configuration file: %v", err)
	}
	if !*SmfConfig.Configuration.KafkaInfo.EnableKafka {
		t.Errorf("Expected Kafka to be enabled by default, was disabled")
	}
}

func TestWebuiUrl(t *testing.T) {
	tests := []struct {
		name       string
		configFile string
		want       string
	}{
		{
			name:       "default webui URL",
			configFile: "../config/smfcfg.yaml",
			want:       "http://webui:5001",
		},
		{
			name:       "custom webui URL",
			configFile: "../config/smfcfg_with_custom_webui_url.yaml",
			want:       "https://myspecialwebui:5002",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore original config
			origSmfConfig := SmfConfig
			t.Cleanup(func() { SmfConfig = origSmfConfig })

			if err := InitConfigFactory(tt.configFile); err != nil {
				t.Logf("error in InitConfigFactory: %v", err)
			}

			got := SmfConfig.Configuration.WebuiUri
			if got != tt.want {
				t.Errorf("The webui URL is not correct. got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestLiBulkSwitchesAreTriState covers the two keys that carry an agreement the standard
// leaves to the deployment, at the layer where an operator's `false` is at risk of becoming
// nothing at all.
//
// The third case is the one worth having: a value that is not a boolean must be refused,
// not read as unset. Unset is the permissive answer for bulk deactivation, so silently
// defaulting a typo would leave the element performing exactly the operation the operator
// wrote the key to withhold. It is the rule the UPF's config already applies to its
// keepalive window.
func TestLiBulkSwitchesAreTriState(t *testing.T) {
	li := func(extra string) string {
		return `configuration:
  li:
    x1Listen: ":8443"
    neId: smf-1` + extra + "\n"
	}

	t.Run("both switches carry through", func(t *testing.T) {
		var cfg Config
		if err := yaml.Unmarshal([]byte(li(`
    deactivateAllTasks: false
    removeAllDestinations: true`)), &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got := cfg.Configuration.Li.DeactivateAllTasks; got == nil || *got {
			t.Errorf("deactivateAllTasks = %v, want a stated false — a dropped restriction leaves "+
				"the element performing the operation the operator withheld", got)
		}
		if got := cfg.Configuration.Li.RemoveAllDestinations; got == nil || !*got {
			t.Errorf("removeAllDestinations = %v, want a stated true", got)
		}
	})

	t.Run("saying nothing is not saying false", func(t *testing.T) {
		var cfg Config
		if err := yaml.Unmarshal([]byte(li("")), &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if cfg.Configuration.Li.DeactivateAllTasks != nil || cfg.Configuration.Li.RemoveAllDestinations != nil {
			t.Error("an li block that states no agreement must leave both unset, so the " +
				"standard's own defaults apply")
		}
	})

	t.Run("a value that is not a boolean is refused", func(t *testing.T) {
		var cfg Config
		if err := yaml.Unmarshal([]byte(li("\n    deactivateAllTasks: perhaps")), &cfg); err == nil {
			t.Errorf("an unparseable value was accepted as %v; it must be refused rather than "+
				"read as unset, which is the permissive answer",
				cfg.Configuration.Li.DeactivateAllTasks)
		}
	})
}
