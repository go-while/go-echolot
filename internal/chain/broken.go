package chain

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// chainRE is Echolot's m/\((\S+) \s (\S+)\)/x, unanchored.  Perl's \s on
// the bytes of broken2.txt is [\t\n\v\f\r ]; Go's \s lacks \v, so the
// classes are spelled out.  Go's regexp picks the submatches a
// backtracking engine would, as Perl does.
var chainRE = regexp.MustCompile(`\(([^\t\n\v\f\r ]+)[\t\n\v\f\r ]([^\t\n\v\f\r ]+)\)`)

// parse returns the two nicks of a chain line, as E:Stats.pm:518 does.
func parse(s string) (left, right string, ok bool) {
	m := chainRE.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// sortUniq sorts byte-wise and drops duplicates (Perl's sort { $a cmp
// $b } grep { ! $unique{$_}++ }).
func sortUniq(list []string) []string {
	l := slices.Clone(list)
	slices.Sort(l)
	return slices.Compact(l)
}

// Compress compresses a list of broken chains as E:Stats.pm:509-555 does.
// num is the number of remailers (Echolot's scalar @$rems).
//   - Each distinct chain "(L R)" counts once for its left nick L and once
//     for its right nick R; "(* R)" adds num more for R, "(L *)" num more
//     for L.
//   - A right nick counted at least num × AllBad times becomes "(* R)", a
//     left nick "(L *)", and the chains they cover go.
//   - Lines that aren't chains are kept as they are.
//   - The result is sorted byte-wise without duplicates.
//
// It follows Echolot's quirks: "*" itself is counted as a nick (so
// enough "(* x)" lines give "(* *)"), and with num 0 every nick of every
// chain becomes "(L *)" and "(* R)".
func Compress(num int, list []string) []string {
	list = sortUniq(list)
	badLeft, badRight := map[string]int{}, map[string]int{}
	for _, c := range list {
		l, r, ok := parse(c)
		if !ok {
			continue // Echolot warns "Could not parse bad chain"
		}
		badRight[r]++
		if l == "*" {
			badRight[r] += num
		}
		badLeft[l]++
		if r == "*" {
			badLeft[l] += num
		}
	}
	threshold := float64(num) * AllBad
	var res []string
	for k, n := range badRight {
		if float64(n) < threshold {
			delete(badRight, k)
			continue
		}
		res = append(res, "(* "+k+")")
	}
	for k, n := range badLeft {
		if float64(n) < threshold {
			delete(badLeft, k)
			continue
		}
		res = append(res, "("+k+" *)")
	}
	for _, c := range list {
		l, r, ok := parse(c)
		if ok {
			if _, ok := badRight[r]; ok {
				continue
			}
			if _, ok := badLeft[l]; ok {
				continue
			}
		}
		res = append(res, c)
	}
	return sortUniq(res)
}

// HardLines splits the text of the operator's broken1.txt or broken2.txt
// into lines as Perl's split /\n/ does (E:Stats.pm:620): empty lines at
// the end go, others stay; an empty text has no lines.  Use nil for a
// missing file.
func HardLines(text string) []string {
	l := strings.Split(text, "\n")
	for len(l) > 0 && l[len(l)-1] == "" {
		l = l[:len(l)-1]
	}
	return l
}

// Broken2Text returns the text of the "Broken type-II remailer chains"
// section of mlist2.txt and mlist.txt, public and private, with chain
// pings on (E:Stats.pm:619-631, 668-670):
//   - hard (HardLines of broken2.txt) goes into both, with the chains of
//     broken: in the public text only those with Public set;
//   - each list is compressed with num, the number of remailers in the
//     private mlist2.txt (all its rows, for both texts);
//   - the lines are joined with "\n", without a final one.
//
// The section is printed even when the text is empty (design §7.3).
// Operator lines aren't simply prepended: they go through the
// compression and the sort like the rest, as in Echolot.
func Broken2Text(broken []Broken, hard []string, num int) (pub, priv string) {
	pubList := slices.Clone(hard)
	privList := slices.Clone(hard)
	for _, b := range broken {
		if b.Public {
			pubList = append(pubList, b.Chain)
		}
		privList = append(privList, b.Chain)
	}
	return strings.Join(Compress(num, pubList), "\n"), strings.Join(Compress(num, privList), "\n")
}

// Broken1Text returns the text of the "Broken type-I remailer chains"
// section with chain pings on.  Echolot evaluates type-I (cpunk) chains
// with the type-I remailers, of which a yamn pinger has none, so the
// section is broken1.txt compressed with num 0 (E:Stats.pm:669): every
// chain "(L R)" in it becomes "(L *)" and "(* R)".
func Broken1Text(hard []string) string {
	return strings.Join(Compress(0, hard), "\n")
}

// String returns the pair as Echolot logs it.
func (p Pair) String() string { return p.A.Addr + " " + p.B.Addr }

// String returns the chain and its counts, for the log.
func (b Broken) String() string {
	return b.Chain + " " + strconv.Itoa(b.Done) + "/" + strconv.Itoa(b.Out)
}
