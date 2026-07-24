package engine

type automaton struct {
	nodes []automatonNode
}

type automatonNode struct {
	next  map[byte]int
	fail  int
	depth int
	out   []keywordHit
}

type keywordHit struct {
	ruleIndex int
	length    int
}

func newAutomaton() *automaton {
	return &automaton{nodes: []automatonNode{{next: map[byte]int{}}}}
}

func (a *automaton) add(keyword []byte, ruleIndex int) {
	if len(keyword) == 0 {
		return
	}
	node := 0
	for i, b := range keyword {
		next, ok := a.nodes[node].next[b]
		if !ok {
			next = len(a.nodes)
			a.nodes[node].next[b] = next
			a.nodes = append(a.nodes, automatonNode{next: map[byte]int{}, depth: i + 1})
		}
		node = next
	}
	a.nodes[node].out = append(a.nodes[node].out, keywordHit{
		ruleIndex: ruleIndex,
		length:    len(keyword),
	})
}

func (a *automaton) build() {
	queue := make([]int, 0, len(a.nodes))
	for _, child := range a.nodes[0].next {
		queue = append(queue, child)
	}

	for head := 0; head < len(queue); head++ {
		current := queue[head]
		for b, child := range a.nodes[current].next {
			fail := a.nodes[current].fail
			for fail != 0 {
				if next, ok := a.nodes[fail].next[b]; ok {
					fail = next
					break
				}
				fail = a.nodes[fail].fail
			}
			if fail == 0 {
				if next, ok := a.nodes[0].next[b]; ok && next != child {
					fail = next
				}
			}
			a.nodes[child].fail = fail
			a.nodes[child].out = append(a.nodes[child].out, a.nodes[fail].out...)
			queue = append(queue, child)
		}
	}
}

func (a *automaton) step(state int, b byte) int {
	for state != 0 {
		if next, ok := a.nodes[state].next[b]; ok {
			return next
		}
		state = a.nodes[state].fail
	}
	if next, ok := a.nodes[0].next[b]; ok {
		return next
	}
	return 0
}

// statePartialMatchLen returns the longest live partial-match length at the
// given automaton state: the deepest keyword that could still extend from this
// state without consuming more bytes. State 0 (root) has no live partial —
// nothing we've consumed so far can extend into a match.
//
// For a state at depth d in the goto trie, every byte we've fed to get here
// is a prefix of at least one keyword (that's the trie invariant), so up to
// d bytes are still "in play". The fail links propagate keyword outs, but
// those are completed matches, not partials; the longest live partial at a
// state is exactly the depth of the deepest trie node reachable from root by
// the path that led here (which the automaton tracks via state, since each
// goto edge descends exactly one level).
//
// We precompute this once at build time as nodeDepth.
func (a *automaton) statePartialMatchLen(state int) int {
	if state <= 0 || state >= len(a.nodes) {
		return 0
	}
	return a.nodes[state].depth
}
