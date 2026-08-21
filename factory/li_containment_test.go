// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestStrictLiBlockDoesNotFailTheConfigurationLoad is a source-level assertion, and it exists
// because the property it guards was already established once and then lost.
//
// `service/li_block_containment_test.go` asserts that the Lawful Interception block cannot return
// from Start. Both of its guards passed while this network function was, in fact, refusing to
// start over a single mistyped LI key — because the refusal had moved one call frame earlier and
// into this package, where neither guard could see it. A guard scoped to where a defect was last
// found does not follow the defect, and it reads as coverage while the property is violated
// somewhere else.
//
// So the rule here is the other half: `strictLiBlock`'s verdict is *recorded*, never returned.
// Returning it fails InitConfigFactory, which fails Initialize, which reaches a Fatalf — taking
// PFCP, the service-based interface, NRF registration and every subscriber's session with it, over
// an optional subsystem. It is also the loudest possible disclosure that this element is
// LI-provisioned: a network function that will not start is visible to every operator, every peer
// and every monitoring system, where a log line is visible only to whoever reads logs.
//
// The refusal still happens, and interception still does not start on it. What changed is who acts
// on it: the LI subsystem, at a point where the ADMF can be told. See LiBlockError.
func TestStrictLiBlockDoesNotFailTheConfigurationLoad(t *testing.T) {
	const file = "factory.go"

	fset := token.NewFileSet()

	parsed, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}

	var (
		found    bool
		recorded bool
	)

	ast.Inspect(parsed, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}

		ident, isIdent := call.Fun.(*ast.Ident)
		if !isIdent || ident.Name != "strictLiBlock" {
			return true
		}

		found = true

		return true
	})

	if !found {
		t.Fatalf("no call to strictLiBlock in %s; if the strict LI decode moved, move this guard "+
			"with it rather than deleting it — the property it holds is that a refused LI block "+
			"never stops the network function", file)
	}

	// The call must be the right-hand side of an assignment to liBlockErr, and nothing else. An
	// `if err := strictLiBlock(...); err != nil { return err }` is the exact shape that caused
	// the regression, and it is an assignment too — so the guard checks the target, not merely
	// that an assignment happened.
	ast.Inspect(parsed, func(n ast.Node) bool {
		assign, isAssign := n.(*ast.AssignStmt)
		if !isAssign || len(assign.Rhs) != 1 {
			return true
		}

		call, isCall := assign.Rhs[0].(*ast.CallExpr)
		if !isCall {
			return true
		}

		ident, isIdent := call.Fun.(*ast.Ident)
		if !isIdent || ident.Name != "strictLiBlock" {
			return true
		}

		for _, lhs := range assign.Lhs {
			if target, ok := lhs.(*ast.Ident); ok && target.Name == "liBlockErr" {
				recorded = true
			}
		}

		return true
	})

	if !recorded {
		t.Errorf("%s: strictLiBlock's verdict is not recorded in liBlockErr. If it is returned "+
			"from InitConfigFactory instead, a single mistyped key in the optional `li` block "+
			"stops this whole network function — an outage, and the loudest way to disclose that "+
			"this element is LI-provisioned. Record it and let the LI subsystem refuse "+
			"interception on it, where the ADMF can be told.", file)
	}
}

// TestTheStrictLiDecodeIsStillStrict guards the other direction. The fix above is a narrow one —
// who acts on the refusal — and it must not be read, or implemented, as backing out the strictness
// that produced it. A mistyped LI key must still be refused; it simply must not take the network
// function down.
func TestTheStrictLiDecodeIsStillStrict(t *testing.T) {
	const body = `info:
  version: 1.0.0
configuration:
  li:
    x1Listen: ":8443"
    neId: smf-1
    keepaliveTimeut: 30s
`

	if err := strictLiBlock([]byte(body)); err == nil {
		t.Error("a misspelled LI key was accepted by the strict decode; the containment fix is " +
			"about who acts on the refusal, not about whether there is one")
	}
}
