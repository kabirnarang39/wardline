package adapter

import (
	"fmt"
	"strconv"
	"strings"
)

// This file implements the general SCIM filter grammar (RFC 7644
// §3.4.2.2), replacing the earlier `<attr> eq "<value>"`-only substring
// heuristic (parseEqFilter, deleted): a real tokenizer + recursive-
// descent parser + AST evaluator, the same shape any real SCIM server
// implementation uses, not a pattern-matched special case. Supports
// every comparison operator the spec defines (eq, ne, co, sw, ew, gt,
// lt, ge, le, pr), the and/or/not logical operators with parentheses,
// and any attribute name a resource actually has -- not hardcoded to
// exactly one field per resource type the way the old heuristic was.
//
// Grammar (RFC 7644 §3.4.2.2, ABNF, "and" binding tighter than "or" --
// the conventional precedence every real implementation uses, since the
// spec's own ABNF is left-recursive and silent on precedence beyond
// that):
//
//	expr   = orExpr
//	orExpr = andExpr ( "or" andExpr )*
//	andExpr = notExpr ( "and" notExpr )*
//	notExpr = [ "not" ] primary
//	primary = "(" orExpr ")" | attrExpr
//	attrExpr = IDENT "pr" | IDENT compareOp compValue
//	compareOp = "eq" | "ne" | "co" | "sw" | "ew" | "gt" | "lt" | "ge" | "le"
//	compValue = STRING | NUMBER | "true" | "false" | "null"

// filterNode is one node of a parsed filter's AST -- evaluate reports
// whether attrs (a resource's own attribute-name -> value map, built
// once per resource by the caller) satisfies this node.
type filterNode interface {
	evaluate(attrs map[string]any) bool
}

type andNode struct{ left, right filterNode }

func (n andNode) evaluate(attrs map[string]any) bool {
	return n.left.evaluate(attrs) && n.right.evaluate(attrs)
}

type orNode struct{ left, right filterNode }

func (n orNode) evaluate(attrs map[string]any) bool {
	return n.left.evaluate(attrs) || n.right.evaluate(attrs)
}

type notNode struct{ inner filterNode }

func (n notNode) evaluate(attrs map[string]any) bool {
	return !n.inner.evaluate(attrs)
}

// attrNode is one `<attr> <op> [<value>]` comparison. op is always
// lowercase (case-folded at parse time -- SCIM operators are
// case-insensitive per the spec).
type attrNode struct {
	attr  string
	op    string
	value any // string, float64, bool, or nil ("null") -- nil for "pr"
}

func (n attrNode) evaluate(attrs map[string]any) bool {
	got, present := attrs[n.attr]
	if n.op == "pr" {
		if !present {
			return false
		}
		// SCIM "pr" means present AND non-empty for string-valued
		// attributes -- a resource with userName: "" should not match
		// `userName pr`, matching every real SCIM server's behavior.
		if s, ok := got.(string); ok {
			return s != ""
		}
		return true
	}
	if !present {
		return false
	}
	switch n.op {
	case "eq":
		return compareEqual(got, n.value)
	case "ne":
		return !compareEqual(got, n.value)
	case "co", "sw", "ew":
		gotStr, gotOK := got.(string)
		wantStr, wantOK := n.value.(string)
		if !gotOK || !wantOK {
			return false
		}
		switch n.op {
		case "co":
			return strings.Contains(gotStr, wantStr)
		case "sw":
			return strings.HasPrefix(gotStr, wantStr)
		default: // "ew"
			return strings.HasSuffix(gotStr, wantStr)
		}
	case "gt", "lt", "ge", "le":
		return compareOrdered(got, n.value, n.op)
	default:
		return false // unreachable: the parser never produces an unknown op
	}
}

func compareEqual(got, want any) bool {
	switch g := got.(type) {
	case string:
		w, ok := want.(string)
		return ok && g == w
	case bool:
		w, ok := want.(bool)
		return ok && g == w
	case float64:
		w, ok := want.(float64)
		return ok && g == w
	default:
		return got == want
	}
}

// compareOrdered handles gt/lt/ge/le -- SCIM defines these for numeric
// and date-time attributes only (never boolean, per RFC 7644 §3.4.2.2's
// own table). Neither User's `active` (bool) nor userName/displayName
// (string identifiers, not ordered by spec) supports these ops in this
// implementation's own resource shapes -- an operator that doesn't
// apply to the attribute's actual value type simply never matches,
// rather than panicking or silently coercing.
func compareOrdered(got, want any, op string) bool {
	g, gOK := got.(float64)
	w, wOK := want.(float64)
	if !gOK || !wOK {
		return false
	}
	switch op {
	case "gt":
		return g > w
	case "lt":
		return g < w
	case "ge":
		return g >= w
	default: // "le"
		return g <= w
	}
}

// --- Tokenizer ---

type tokenKind int

const (
	tokIdent tokenKind = iota
	tokString
	tokNumber
	tokLParen
	tokRParen
	tokEOF
)

type token struct {
	kind tokenKind
	text string  // raw text for tokIdent; unescaped value for tokString
	num  float64 // parsed value for tokNumber
}

// tokenizeFilter splits a raw SCIM filter string into tokens. Returns an
// error on an unterminated string literal or a character that starts no
// valid token -- the parser never sees a malformed token stream.
func tokenizeFilter(s string) ([]token, error) {
	var toks []token
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(':
			toks = append(toks, token{kind: tokLParen})
			i++
		case c == ')':
			toks = append(toks, token{kind: tokRParen})
			i++
		case c == '"':
			j := i + 1
			var sb strings.Builder
			closed := false
			for j < n {
				if s[j] == '\\' && j+1 < n {
					// Minimal escape handling -- \" and \\ only, the two
					// SCIM filter string values actually need (RFC 7644
					// borrows JSON string escaping); anything else passes
					// through literally rather than rejecting a filter
					// over an escape sequence this narrow implementation
					// doesn't special-case.
					sb.WriteByte(s[j+1])
					j += 2
					continue
				}
				if s[j] == '"' {
					closed = true
					j++
					break
				}
				sb.WriteByte(s[j])
				j++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string literal")
			}
			toks = append(toks, token{kind: tokString, text: sb.String()})
			i = j
		case (c >= '0' && c <= '9') || (c == '-' && i+1 < n && s[i+1] >= '0' && s[i+1] <= '9'):
			j := i + 1
			for j < n && (s[j] == '.' || (s[j] >= '0' && s[j] <= '9')) {
				j++
			}
			val, err := strconv.ParseFloat(s[i:j], 64)
			if err != nil {
				return nil, fmt.Errorf("invalid number %q", s[i:j])
			}
			toks = append(toks, token{kind: tokNumber, num: val})
			i = j
		case isIdentStart(c):
			j := i + 1
			for j < n && isIdentPart(s[j]) {
				j++
			}
			toks = append(toks, token{kind: tokIdent, text: s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q in filter", c)
		}
	}
	toks = append(toks, token{kind: tokEOF})
	return toks, nil
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '.' || c == ':'
}

// --- Recursive-descent parser ---

type filterParser struct {
	toks []token
	pos  int
}

func (p *filterParser) peek() token { return p.toks[p.pos] }
func (p *filterParser) next() token { t := p.toks[p.pos]; p.pos++; return t }

// isKeyword reports whether an identifier token's text case-insensitively
// matches want -- every SCIM filter keyword (and/or/not/pr/eq/ne/co/sw/
// ew/gt/lt/ge/le/true/false/null) is case-insensitive per the spec.
func isKeyword(t token, want string) bool {
	return t.kind == tokIdent && strings.EqualFold(t.text, want)
}

func (p *filterParser) parseOr() (filterNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for isKeyword(p.peek(), "or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}
	return left, nil
}

func (p *filterParser) parseAnd() (filterNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for isKeyword(p.peek(), "and") {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = andNode{left, right}
	}
	return left, nil
}

func (p *filterParser) parseNot() (filterNode, error) {
	if isKeyword(p.peek(), "not") {
		p.next()
		inner, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return notNode{inner}, nil
	}
	return p.parsePrimary()
}

func (p *filterParser) parsePrimary() (filterNode, error) {
	if p.peek().kind == tokLParen {
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("expected closing parenthesis")
		}
		p.next()
		return inner, nil
	}
	return p.parseAttrExpr()
}

var compareOps = map[string]bool{
	"eq": true, "ne": true, "co": true, "sw": true, "ew": true,
	"gt": true, "lt": true, "ge": true, "le": true,
}

func (p *filterParser) parseAttrExpr() (filterNode, error) {
	attrTok := p.next()
	if attrTok.kind != tokIdent || isKeyword(attrTok, "and") || isKeyword(attrTok, "or") || isKeyword(attrTok, "not") {
		return nil, fmt.Errorf("expected attribute name")
	}
	opTok := p.next()
	if opTok.kind != tokIdent {
		return nil, fmt.Errorf("expected operator after attribute %q", attrTok.text)
	}
	op := strings.ToLower(opTok.text)
	if op == "pr" {
		return attrNode{attr: attrTok.text, op: "pr"}, nil
	}
	if !compareOps[op] {
		return nil, fmt.Errorf("unsupported operator %q", opTok.text)
	}
	valTok := p.next()
	var value any
	switch {
	case valTok.kind == tokString:
		value = valTok.text
	case valTok.kind == tokNumber:
		value = valTok.num
	case isKeyword(valTok, "true"):
		value = true
	case isKeyword(valTok, "false"):
		value = false
	case isKeyword(valTok, "null"):
		value = nil
	default:
		return nil, fmt.Errorf("expected a comparison value after operator %q", op)
	}
	return attrNode{attr: attrTok.text, op: op, value: value}, nil
}

// parseSCIMFilter parses rawFilter into a filterNode -- ok is false for
// an empty filter (no filtering requested, the caller's existing
// unfiltered-list behavior); err is non-nil for anything that fails to
// parse as a well-formed SCIM filter expression, so the caller can
// return the same 400 the earlier narrow heuristic did, now for a
// precise parse error instead of "outside the one supported shape".
func parseSCIMFilter(rawFilter string) (node filterNode, ok bool, err error) {
	rawFilter = strings.TrimSpace(rawFilter)
	if rawFilter == "" {
		return nil, false, nil
	}
	toks, err := tokenizeFilter(rawFilter)
	if err != nil {
		return nil, false, err
	}
	p := &filterParser{toks: toks}
	n, err := p.parseOr()
	if err != nil {
		return nil, false, err
	}
	if p.peek().kind != tokEOF {
		return nil, false, fmt.Errorf("unexpected trailing input after filter expression")
	}
	return n, true, nil
}
