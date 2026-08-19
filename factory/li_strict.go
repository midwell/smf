// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"fmt"

	"go.yaml.in/yaml/v4"
)

// strictLiBlock re-decodes the `li` block on its own, refusing a key this element does not
// model.
//
// **A misspelled LI key is silently dropped, and the defaults it lands on are the dangerous
// ones.** A typo'd `keepaliveTimeout` leaves the X1 fail-safe *off*, so the element holds tasking
// nothing will ever reclaim while looking healthy. A typo'd `admfUrl` leaves the fault channel a
// no-op, so every condition this element is required to report goes nowhere — including the report
// that would have said the configuration was wrong. In both cases the operator wrote the setting,
// the element ignored it, and nothing anywhere says so.
//
// **Scoped to the `li` block, deliberately.** Decoding the whole configuration strictly would
// refuse upstream keys this fork does not model, which is a different and much larger change: the
// fork tracks an upstream that adds fields, and a deployment carrying one would stop starting. The
// property to hold is narrow — a mistyped LI key must not reach a default — and so is the check.
//
// The block is isolated first and decoded strictly second, because strictness lives on the decode
// and a decode covers everything it is given. The lenient first pass models nothing but the path
// to the block, so no key outside it is visible to be refused.
func strictLiBlock(content []byte) error {
	// Only the path to the block. This struct must not grow: modelling anything else here would
	// make it a second, diverging definition of the configuration.
	var outer struct {
		Configuration struct {
			Li yaml.Node `yaml:"li"`
		} `yaml:"configuration"`
	}
	if err := yaml.Unmarshal(content, &outer); err != nil {
		// Anything that makes the file undecodable is the real decode's to report, with its own
		// message. This check has nothing to add about it.
		return nil
	}

	block := &outer.Configuration.Li
	if block.Kind == 0 {
		// No `li` block at all: interception is off, and there is nothing to be strict about.
		return nil
	}

	// Round-tripped so the strict pass sees the block and only the block. One small mapping, once,
	// at startup.
	raw, err := yaml.Marshal(block)
	if err != nil {
		return nil
	}

	var li Li
	if err := yaml.Load(raw, &li, yaml.WithKnownFields()); err != nil {
		return fmt.Errorf("configuration.li: %w — a key this element does not recognise is a "+
			"setting that never reaches it, and the defaults it leaves in place are the unsafe ones: "+
			"an unread keepaliveTimeout leaves the X1 fail-safe off, and an unread admfUrl leaves "+
			"this element with no channel to report that on", err)
	}

	return nil
}
