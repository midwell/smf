// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// TestLIBlockCannotReturnFromStart is a source-level assertion, and it is deliberate.
//
// The defect it guards was control flow, not a value: the Lawful Interception block in
// Start() answered an unreadable configuration value with `return`, which returns from
// *Start* rather than from LI initialisation. Everything after it never ran — PFCP, the
// service-based interface, registration with the network — and because Start has no
// error to return, the process then exited 0. A mistyped duration in an optional block
// became a restart loop carrying a success exit code, diagnosed by a log line that is
// required to say nothing about which subsystem declined.
//
// It survived a unit test of the parse helper, which asserted the value and never
// reached the control flow that was wrong. Start itself cannot be called from a test: it
// binds ports, registers with an NRF and does not return. So the property is asserted
// where it actually lives — in the shape of the function — rather than not at all.
//
// The rule is narrow on purpose: no `return` inside the LI block. A refusal there must
// stop interception and nothing else, which means falling through to the code below it.
func TestLIBlockCannotReturnFromStart(t *testing.T) {
	const file = "init.go"

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}

	start := findMethod(parsed, "Start")
	if start == nil {
		t.Fatalf("no Start method found in %s; this test is guarding the wrong function", file)
	}

	block := findLIBlock(start)
	if block == nil {
		t.Fatalf("no `if li := ...Configuration.Li; li != nil` block found in Start; if the " +
			"Lawful Interception wiring moved, move this guard with it rather than deleting it")
	}

	ast.Inspect(block, func(n ast.Node) bool {
		// A nested function literal has its own return, which is its own business.
		if _, isFunc := n.(*ast.FuncLit); isFunc {
			return false
		}
		if ret, isReturn := n.(*ast.ReturnStmt); isReturn {
			t.Errorf("%s: the Lawful Interception block returns from Start. That stops every "+
				"other subsystem this network function runs, and Start has no error to carry "+
				"the reason — the process exits 0 and restarts. Scope the refusal to LI.",
				fset.Position(ret.Pos()))
		}

		return true
	})
}

// findMethod returns the named method declaration, whatever its receiver.
func findMethod(f *ast.File, name string) *ast.FuncDecl {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Recv != nil && fn.Name.Name == name {
			return fn
		}
	}

	return nil
}

// findLIBlock returns the body of the `if li := …Configuration.Li; li != nil` statement,
// located by its initialising assignment rather than by position.
func findLIBlock(fn *ast.FuncDecl) *ast.BlockStmt {
	var found *ast.BlockStmt

	ast.Inspect(fn, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Init == nil {
			return true
		}
		assign, ok := ifStmt.Init.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 {
			return true
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || ident.Name != "li" {
			return true
		}
		if len(assign.Rhs) == 1 && strings.HasSuffix(exprString(assign.Rhs[0]), ".Li") {
			found = ifStmt.Body

			return false
		}

		return true
	})

	return found
}

// exprString renders a selector chain well enough to recognise `….Configuration.Li`.
func exprString(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}

	return "." + sel.Sel.Name
}

// TestLIBlockRefusalIsNotAttributable is the other half of the containment rule, and
// it guards the direction that is easy to get backwards.
//
// Scoping the refusal to LI (the test above) keeps the network function running. What
// that leaves is *what the refusal says*. An element that declines to intercept because
// it cannot read its own configuration must be indistinguishable, to anybody reading
// this network function's general logs, from an element that was never given an LI
// block at all — network-element-level undetectability (TS 33.127). Two things break
// that here, and both are one careless edit away:
//
//   - Echoing the error. `lawfulintercept.Init` returns text that names the subsystem
//     ("li: no network element identifier configured", a failure to load LI credentials,
//     an X1 listen address that would not bind). A `%v` of it on InitLog publishes to
//     every operator and every log shipper that this element is LI-provisioned. The
//     error is not lost: from inside Init the ADMF is told over X1, which is the channel
//     that is permitted to know.
//   - Terminating. A `Fatalln` or a `panic` here refuses the same way the `return` did,
//     and discloses more loudly than any log line could — a network function that does
//     not serve is visible to every peer and every monitoring system.
//
// So the rule for this block: no process-terminating call, and any log line carries a
// constant that names no part of interception.
func TestLIBlockRefusalIsNotAttributable(t *testing.T) {
	const file = "init.go"

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}

	start := findMethod(parsed, "Start")
	if start == nil {
		t.Fatalf("no Start method found in %s; this test is guarding the wrong function", file)
	}

	block := findLIBlock(start)
	if block == nil {
		t.Fatalf("no `if li := ...Configuration.Li; li != nil` block found in Start; if the " +
			"Lawful Interception wiring moved, move this guard with it rather than deleting it")
	}

	ast.Inspect(block, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		callee := calleeName(call)

		if terminatesProcess(callee) {
			t.Errorf("%s: the Lawful Interception block calls %s. That stops the network "+
				"function over its LI configuration, which is the same disclosure a log line "+
				"naming the subsystem would make, arrived at through availability and visible "+
				"to every peer and every monitoring system. Report it to the ADMF from inside "+
				"Init and carry on.", fset.Position(call.Pos()), callee)

			return true
		}
		if !writesToLog(callee) {
			return true
		}

		for _, arg := range call.Args {
			lit, isLit := arg.(*ast.BasicLit)
			if !isLit || lit.Kind != token.STRING {
				t.Errorf("%s: the Lawful Interception block logs a runtime value (%s). Every "+
					"value in scope here is LI configuration or an error from LI "+
					"initialisation, and their text names the subsystem — which on this "+
					"network function's general log tells every operator that this element is "+
					"LI-provisioned. Log a constant; the ADMF is told over X1 from inside Init.",
					fset.Position(arg.Pos()), exprSummary(arg))

				continue
			}
			if word := attributingWord(lit.Value); word != "" {
				t.Errorf("%s: the Lawful Interception block logs a message containing %q, which "+
					"attributes the refusal to interception on this network function's general "+
					"log. Say that an optional subsystem did not start, and no more.",
					fset.Position(lit.Pos()), word)
			}
		}

		return true
	})
}

// calleeName returns the called function's own name — the selector's last element for
// a method, the identifier for a plain call — and "" for anything else.
func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name
	case *ast.Ident:
		return fn.Name
	}

	return ""
}

// terminatesProcess reports whether a call by this name ends the process. The logging
// levels that exit are included: on this path Fatalln and return are the same defect.
func terminatesProcess(name string) bool {
	switch name {
	case "panic", "Exit", "Goexit",
		"Fatal", "Fatalf", "Fatalln",
		"Panic", "Panicf", "Panicln":
		return true
	}

	return false
}

// writesToLog reports whether a call by this name writes to a log. Matched by prefix so
// a level this element does not use yet is covered before it is used.
func writesToLog(name string) bool {
	for _, level := range []string{"Error", "Warn", "Info", "Debug", "Trace", "Print", "Log"} {
		if strings.HasPrefix(name, level) {
			return true
		}
	}

	return false
}

// attributingWord returns the first token of a log message that would attribute it to
// interception, or "" if the message names nothing.
//
// The short tokens are matched as whole words on purpose. "li" is inside "initialise"
// and "poi" is inside "point", and a guard that failed on the message this block
// actually logs — "an optional subsystem failed to initialise" — would be deleted
// rather than obeyed.
func attributingWord(quoted string) string {
	text := quoted
	if unquoted, err := strconv.Unquote(quoted); err == nil {
		text = unquoted
	}
	text = strings.ToLower(text)

	// Compounds, where a substring cannot be a false positive.
	for _, s := range []string{"lawful", "intercept", "admf", "warrant", "x1listen", "mdf"} {
		if strings.Contains(text, s) {
			return s
		}
	}

	words := map[string]bool{
		"li": true, "lipf": true, "poi": true, "iri": true, "cc": true,
		"x1": true, "x2": true, "x3": true, "x0": true,
		"xid": true, "seid": true, "target": true, "targets": true,
		"tasking": true, "task": true, "keepalive": true, "delivery": true,
	}
	for _, word := range strings.FieldsFunc(text, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if words[word] {
			return word
		}
	}

	return ""
}

// exprSummary names an argument well enough to point at it in a failure.
func exprSummary(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprSummary(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return calleeName(v) + "(…)"
	}

	return "a runtime value"
}
