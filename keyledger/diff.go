package keyledger

import "sort"

type Change struct {
	Kind        string  `json:"kind"`
	Fingerprint string  `json:"fingerprint"`
	Before      []Entry `json:"before"`
	After       []Entry `json:"after"`
}

type Difference struct {
	Schema      string   `json:"schema"`
	Changed     bool     `json:"changed"`
	BeforeCount int      `json:"before_count"`
	AfterCount  int      `json:"after_count"`
	Changes     []Change `json:"changes"`
}

// Compare treats each fingerprint's ordered option sets as a multiset.
// Entry order, line numbers and comments do not change authorization identity.
// Reordering options within one record is conservatively reported as drift.
func Compare(before, after Inventory) Difference {
	result := Difference{Schema: "rudy.keyledger.diff/v1", BeforeCount: len(before.Entries), AfterCount: len(after.Entries), Changes: []Change{}}
	old, next := map[string][]Entry{}, map[string][]Entry{}
	fingerprints := map[string]bool{}
	for _, entry := range before.Entries {
		old[entry.Fingerprint] = append(old[entry.Fingerprint], entry)
		fingerprints[entry.Fingerprint] = true
	}
	for _, entry := range after.Entries {
		next[entry.Fingerprint] = append(next[entry.Fingerprint], entry)
		fingerprints[entry.Fingerprint] = true
	}
	keys := make([]string, 0, len(fingerprints))
	for key := range fingerprints {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, fingerprint := range keys {
		left, right := old[fingerprint], next[fingerprint]
		counts := map[string]int{}
		for _, entry := range left {
			counts[optionSignature(entry.Options)]++
		}
		for _, entry := range right {
			counts[optionSignature(entry.Options)]--
		}
		changed := false
		for _, count := range counts {
			changed = changed || count != 0
		}
		if !changed {
			continue
		}
		kind := "authorization-changed"
		if len(left) == 0 {
			kind = "key-added"
			left = []Entry{}
		}
		if len(right) == 0 {
			kind = "key-removed"
			right = []Entry{}
		}
		result.Changes = append(result.Changes, Change{kind, fingerprint, left, right})
	}
	result.Changed = len(result.Changes) != 0
	return result
}
