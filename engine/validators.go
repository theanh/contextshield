package engine

import (
	"math"
	"strconv"
	"strings"
	"unicode"
)

func validateCandidate(name string, value []byte) bool {
	text := string(value)
	switch name {
	case "entropy":
		return hasHighEntropy(text)
	case "luhn":
		return validLuhn(digitsOnly(text))
	case "iin_prefix":
		return validPANIssuer(digitsOnly(text))
	case "length_per_network":
		return validPANLength(digitsOnly(text))
	case "iban_mod97":
		return validIBANMod97(text)
	case "iban_country_length":
		return validIBANCountryLength(text)
	case "ssn_range":
		return validSSNRange(text)
	default:
		return false
	}
}

func digitsOnly(text string) string {
	var b strings.Builder
	for _, r := range text {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hasHighEntropy(text string) bool {
	if len(text) < 32 {
		return false
	}
	counts := map[rune]int{}
	for _, r := range text {
		counts[r]++
	}
	if len(counts) < 8 {
		return false
	}
	var entropy float64
	length := float64(len([]rune(text)))
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy >= 3.5
}

func validLuhn(digits string) bool {
	if len(digits) == 0 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

func validPANIssuer(digits string) bool {
	if digits == "" {
		return false
	}
	if digits[0] == '4' {
		return true
	}
	if hasPrefixNumberBetween(digits, 2, 51, 55) {
		return true
	}
	if hasPrefixNumberBetween(digits, 4, 2221, 2720) {
		return true
	}
	if strings.HasPrefix(digits, "34") || strings.HasPrefix(digits, "37") {
		return true
	}
	if strings.HasPrefix(digits, "6011") || strings.HasPrefix(digits, "65") {
		return true
	}
	if hasPrefixNumberBetween(digits, 3, 644, 649) {
		return true
	}
	return false
}

func validPANLength(digits string) bool {
	switch {
	case strings.HasPrefix(digits, "34"), strings.HasPrefix(digits, "37"):
		return len(digits) == 15
	case strings.HasPrefix(digits, "4"):
		return len(digits) == 13 || len(digits) == 16 || len(digits) == 19
	case hasPrefixNumberBetween(digits, 2, 51, 55), hasPrefixNumberBetween(digits, 4, 2221, 2720):
		return len(digits) == 16
	case strings.HasPrefix(digits, "6011"), strings.HasPrefix(digits, "65"), hasPrefixNumberBetween(digits, 3, 644, 649):
		return len(digits) == 16 || len(digits) == 19
	default:
		return false
	}
}

func hasPrefixNumberBetween(text string, width, minValue, maxValue int) bool {
	if len(text) < width {
		return false
	}
	n, err := strconv.Atoi(text[:width])
	if err != nil {
		return false
	}
	return n >= minValue && n <= maxValue
}

func validIBANCountryLength(text string) bool {
	iban := normalizedIBAN(text)
	if len(iban) < 4 {
		return false
	}
	want, ok := ibanLengths[iban[:2]]
	return ok && len(iban) == want
}

func validIBANMod97(text string) bool {
	iban := normalizedIBAN(text)
	if len(iban) < 4 {
		return false
	}
	rearranged := iban[4:] + iban[:4]
	remainder := 0
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			remainder = (remainder*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			n := int(r-'A') + 10
			remainder = (remainder*100 + n) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

func normalizedIBAN(text string) string {
	var b strings.Builder
	for _, r := range text {
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28,
	"BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
	"CH": 21, "CR": 22, "CY": 28, "CZ": 24,
	"DE": 22, "DK": 18, "DO": 28,
	"EE": 20, "ES": 24,
	"FI": 18, "FO": 18, "FR": 27,
	"GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
	"HR": 21, "HU": 28,
	"IE": 22, "IL": 23, "IS": 26, "IT": 27,
	"JO": 30,
	"KW": 30, "KZ": 20,
	"LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
	"MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30,
	"NL": 18, "NO": 15,
	"PK": 24, "PL": 28, "PS": 29, "PT": 25,
	"QA": 29,
	"RO": 24, "RS": 22,
	"SA": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
	"TN": 24, "TR": 26,
	"UA": 29,
	"VA": 22, "VG": 24,
	"XK": 20,
}

func validSSNRange(text string) bool {
	digits := digitsOnly(text)
	if len(digits) != 9 {
		return false
	}
	area, err := strconv.Atoi(digits[:3])
	if err != nil {
		return false
	}
	group := digits[3:5]
	serial := digits[5:]
	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	if digits == "078051120" || digits == "219099999" {
		return false
	}
	return true
}
