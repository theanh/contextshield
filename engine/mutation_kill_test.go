package engine

import (
	"testing"
)

// This file hardens the engine test suite against surviving mutants found by
// gremlins mutation testing. Tests are white-box (package engine) so the pure
// byte-classification helpers and validators can be pinned at their exact
// boundaries. Style: data-provider tables, no logic, no branching helpers.

// --- byte classifiers -------------------------------------------------------

func TestIsUpper(t *testing.T) {
	cases := []struct {
		name string
		in   byte
		want bool
	}{
		{"A lower boundary", 'A', true},
		{"Z upper boundary", 'Z', true},
		{"M middle", 'M', true},
		{"at sign just below A", '@', false}, // '@' == 0x40, 'A' == 0x41
		{"bracket just above Z", '[', false}, // '[' == 0x5B, 'Z' == 0x5A
		{"lowercase a", 'a', false},
		{"digit 0", '0', false},
		{"space", ' ', false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUpper(tc.in); got != tc.want {
				t.Fatalf("isUpper(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsDigit(t *testing.T) {
	cases := []struct {
		name string
		in   byte
		want bool
	}{
		{"0 lower boundary", '0', true},
		{"9 upper boundary", '9', true},
		{"5 middle", '5', true},
		{"slash just below 0", '/', false}, // '/' == 0x2F, '0' == 0x30
		{"colon just above 9", ':', false}, // ':' == 0x3A, '9' == 0x39
		{"letter a", 'a', false},
		{"letter A", 'A', false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDigit(tc.in); got != tc.want {
				t.Fatalf("isDigit(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsAlphaNum(t *testing.T) {
	cases := []struct {
		name string
		in   byte
		want bool
	}{
		{"A", 'A', true},
		{"Z", 'Z', true},
		{"a lower boundary", 'a', true},
		{"z upper boundary", 'z', true},
		{"0", '0', true},
		{"9", '9', true},
		{"at sign below A", '@', false},     // 0x40
		{"bracket above Z", '[', false},     // 0x5B
		{"backtick below a", '`', false},    // 0x60, 'a' == 0x61
		{"brace above z", '{', false},       // 0x7B, 'z' == 0x7A
		{"slash below 0", '/', false},       // 0x2F
		{"colon above 9", ':', false},       // 0x3A
		{"hyphen", '-', false},
		{"space", ' ', false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAlphaNum(tc.in); got != tc.want {
				t.Fatalf("isAlphaNum(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestLowerASCII(t *testing.T) {
	cases := []struct {
		name string
		in   byte
		want byte
	}{
		{"A folds to a", 'A', 'a'},
		{"Z folds to z", 'Z', 'z'},
		{"M folds to m", 'M', 'm'},
		{"a stays a", 'a', 'a'},
		{"z stays z", 'z', 'z'},
		{"0 stays 0", '0', '0'},
		{"at sign unchanged", '@', '@'}, // just below 'A'
		{"bracket unchanged", '[', '['}, // just above 'Z'
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lowerASCII(tc.in); got != tc.want {
				t.Fatalf("lowerASCII(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFoldASCII(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"mixed case", "AbCdZ", "abcdz"},
		{"boundary letters", "AZ", "az"},
		{"digits and symbols untouched", "0@[", "0@["},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(foldASCII([]byte(tc.in))); got != tc.want {
				t.Fatalf("foldASCII(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// --- candidate-start classifiers -------------------------------------------

func TestIsDigitCandidateStart(t *testing.T) {
	cases := []struct {
		name string
		text string
		pos  int
		want bool
	}{
		{"zero at start", "0", 0, true},
		{"nine at start", "9", 0, true},
		{"letter at start not a candidate", "a", 0, false}, // invert_logical guard
		{"slash below 0", "/", 0, false},
		{"colon above 9", ":", 0, false},
		{"digit after non-digit is a start", "a5", 1, true},
		{"digit after zero is not a start", "05", 1, false}, // prev '0' boundary
		{"digit after nine is not a start", "95", 1, false}, // prev '9' boundary
		{"digit after middle digit is not a start", "55", 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDigitCandidateStart([]byte(tc.text), tc.pos); got != tc.want {
				t.Fatalf("isDigitCandidateStart(%q, %d) = %v, want %v", tc.text, tc.pos, got, tc.want)
			}
		})
	}
}

func TestIsIBANCandidateStart(t *testing.T) {
	cases := []struct {
		name string
		text string
		pos  int
		want bool
	}{
		{"valid iban shape at start", "GB12", 0, true},
		{"too short guards against oob", "AB1", 0, false}, // pos+3 >= len guard
		{"lowercase first char", "aB12", 0, false},        // first && chain
		{"lowercase second char", "Ab12", 0, false},
		{"third char not digit", "GBA2", 0, false},
		{"fourth char not digit", "GB1A", 0, false},
		{"prev is space so candidate", " GB12", 1, true},
		{"prev is alnum so not candidate", "xGB12", 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isIBANCandidateStart([]byte(tc.text), tc.pos); got != tc.want {
				t.Fatalf("isIBANCandidateStart(%q, %d) = %v, want %v", tc.text, tc.pos, got, tc.want)
			}
		})
	}
}

// TestStreamIBANCandidateDecision pins the 0/1/2 triage including the guard
// boundaries that panic under mutation (out-of-range pos) and the two-digit
// tail conjunction.
func TestStreamIBANCandidateDecision(t *testing.T) {
	cases := []struct {
		name string
		text string
		pos  int
		want int
	}{
		{"valid candidate", "GB12", 0, 1},
		{"pos at len returns 0 not oob", "GB12", 4, 0},
		{"negative pos returns 0 not oob", "GB12", -1, 0},
		{"only third char digit fails conjunction", "GB1X", 0, 0},
		{"promising prefix needs more bytes", "GB", 0, 2},
		{"single upper needs second char", "G", 0, 2},
		{"second char not upper", "Gb12", 0, 0},
		{"first char not upper", "gB12", 0, 0},
		{"prev alnum rejects", "xGB12", 1, 0},
		{"prev space accepts", " GB12", 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := streamIBANCandidateDecision([]byte(tc.text), tc.pos); got != tc.want {
				t.Fatalf("streamIBANCandidateDecision(%q, %d) = %d, want %d", tc.text, tc.pos, got, tc.want)
			}
		})
	}
}

// --- validators -------------------------------------------------------------

func TestDigitsOnly(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"keeps zero boundary", "0", "0"},
		{"keeps nine boundary", "9", "9"},
		{"drops slash below zero", "/", ""},
		{"drops colon above nine", ":", ""},
		{"strips letters and separators", "4111-1111 abc", "41111111"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := digitsOnly(tc.in); got != tc.want {
				t.Fatalf("digitsOnly(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidLuhn(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"valid visa", "4111111111111111", true},
		{"invalid visa off by one", "4111111111111112", false},
		{"valid amex", "378282246310005", true},
		{"empty is invalid", "", false},
		{"single zero valid", "0", true},
		{"valid mastercard", "5105105105105100", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validLuhn(tc.in); got != tc.want {
				t.Fatalf("validLuhn(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidPANIssuer(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"visa 4", "4111111111111111", true},
		{"mastercard 51", "5105105105105100", true},
		{"mastercard 55", "5599999999999999", true},
		{"mastercard 2221", "2221000000000000", true},
		{"mastercard 2720", "2720000000000000", true},
		{"amex 34", "340000000000000", true},   // kills invert_logical on 34/37
		{"amex 37", "370000000000000", true},   // kills invert_logical on 34/37
		{"discover 6011", "6011000000000000", true},
		{"discover 65", "6500000000000000", true}, // kills invert_logical on 6011/65
		{"discover 644", "6440000000000000", true},
		{"discover 649", "6490000000000000", true},
		{"below mastercard range 50", "5000000000000000", false},
		{"above mastercard range 56", "5600000000000000", false},
		{"unknown 9", "9999999999999999", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validPANIssuer(tc.in); got != tc.want {
				t.Fatalf("validPANIssuer(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidPANLength(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"visa 13", "4222222222222", true},         // kills ==13 negation
		{"visa 16", "4111111111111111", true},
		{"visa 19", "4111111111111111222", true},   // kills ==19 negation
		{"visa 14 invalid", "42222222222222", false},
		{"amex 15", "378282246310005", true},
		{"amex 14 invalid", "37828224631000", false},
		{"mastercard 16", "5105105105105100", true},
		{"mastercard 15 invalid", "510510510510510", false},
		{"discover 16", "6011000000000000", true},
		{"discover 19", "6011000000000000123", true},
		{"unknown prefix", "9999999999999999", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validPANLength(tc.in); got != tc.want {
				t.Fatalf("validPANLength(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestHasPrefixNumberBetween(t *testing.T) {
	cases := []struct {
		name     string
		text     string
		width    int
		minValue int
		maxValue int
		want     bool
	}{
		{"exactly at min", "51", 2, 51, 55, true},   // kills n>=min boundary
		{"exactly at max", "55", 2, 51, 55, true},   // kills n<=max boundary
		{"mid range", "53", 2, 51, 55, true},
		{"one below min", "50", 2, 51, 55, false},   // kills && -> || invert
		{"one above max", "56", 2, 51, 55, false},   // kills && -> || invert
		{"text shorter than width", "5", 2, 51, 55, false}, // len<width guard
		{"width equals length parses", "644", 3, 644, 649, true},
		{"non-numeric prefix", "5a", 2, 51, 55, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasPrefixNumberBetween(tc.text, tc.width, tc.minValue, tc.maxValue)
			if got != tc.want {
				t.Fatalf("hasPrefixNumberBetween(%q,%d,%d,%d) = %v, want %v",
					tc.text, tc.width, tc.minValue, tc.maxValue, got, tc.want)
			}
		})
	}
}

func TestValidSSNRange(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"ordinary valid", "123-45-6789", true},
		{"area 899 valid just below 900", "899-12-3456", true},
		{"area 900 invalid boundary", "900-12-3456", false}, // kills area>=900 boundary
		{"area 901 invalid", "901-12-3456", false},
		{"area zero invalid", "000-12-3456", false},
		{"area 666 invalid", "666-12-3456", false},
		{"group all zero invalid", "123-00-6789", false},
		{"serial all zero invalid", "123-45-0000", false},
		{"advertising ssn invalid", "078-05-1120", false},
		{"promo ssn invalid", "219-09-9999", false},
		{"not nine digits invalid", "123-45-678", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validSSNRange(tc.in); got != tc.want {
				t.Fatalf("validSSNRange(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidIBANCountryLength(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"valid GB length 22", "GB82WEST12345698765432", true},
		{"GB wrong length", "GB8212345", false}, // kills ok && len==want -> ok || ...
		{"GB one short", "GB82WEST1234569876543", false},
		{"unknown country correct-ish length", "ZZ82WEST12345698765432", false},
		{"too short below four", "GB1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validIBANCountryLength(tc.in); got != tc.want {
				t.Fatalf("validIBANCountryLength(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidIBANMod97(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"valid GB iban", "GB82WEST12345698765432", true},
		{"invalid check digits", "GB00WEST12345698765432", false},
		{"empty", "", false},
		{"non-alnum char rejects", "GB82WEST12345698765*32", false},
		{"four-char length boundary still validates mod97", "AA75", true}, // kills len<4 -> len<=4
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validIBANMod97(tc.in); got != tc.want {
				t.Fatalf("validIBANMod97(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestHasHighEntropy(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"high entropy 32 char secret", "Qa7xP2mN9vL4sT8rY1uI6oE3wA5dF0gH", true},
		{"too short below 32", "Qa7xP2mN9vL4sT8rY1uI6oE3wA5dF0g", false},
		{"32 chars all same low entropy", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"32 chars few distinct symbols", "ABABABABABABABABABABABABABABABAB", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasHighEntropy(tc.in); got != tc.want {
				t.Fatalf("hasHighEntropy(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// --- validateRule -----------------------------------------------------------

func TestValidateRuleConfidenceBounds(t *testing.T) {
	cases := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{"confidence zero ok", Rule{ID: "r", Class: "c", Pattern: "x", MaxMatchLen: 4, Confidence: 0}, false},
		{"confidence half ok", Rule{ID: "r", Class: "c", Pattern: "x", MaxMatchLen: 4, Confidence: 0.5}, false},
		{"confidence one is allowed for deterministic rules", Rule{ID: "r", Class: "c", Pattern: "x", MaxMatchLen: 4, Confidence: 1.0}, false}, // kills >1 -> >=1
		{"confidence above one rejected", Rule{ID: "r", Class: "c", Pattern: "x", MaxMatchLen: 4, Confidence: 1.5}, true},                      // kills || -> &&
		{"confidence below zero rejected", Rule{ID: "r", Class: "c", Pattern: "x", MaxMatchLen: 4, Confidence: -0.1}, true},
		{"missing id rejected", Rule{Class: "c", Pattern: "x", MaxMatchLen: 4}, true},
		{"missing class rejected", Rule{ID: "r", Pattern: "x", MaxMatchLen: 4}, true},
		{"missing pattern rejected", Rule{ID: "r", Class: "c", MaxMatchLen: 4}, true},
		{"zero max match len rejected", Rule{ID: "r", Class: "c", Pattern: "x", MaxMatchLen: 0}, true},
		{"negative max match len rejected", Rule{ID: "r", Class: "c", Pattern: "x", MaxMatchLen: -1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRule(tc.rule)
			if tc.wantErr && err == nil {
				t.Fatalf("validateRule(%+v) = nil, want error", tc.rule)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateRule(%+v) = %v, want nil", tc.rule, err)
			}
		})
	}
}
