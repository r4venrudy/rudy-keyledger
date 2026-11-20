package keyledger

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDiffIgnoresEntryOrderAndComments(t *testing.T) {
	first := "restrict,command=\"hello\" ssh-ed25519 " + ed(7)
	second := "ssh-ed25519 " + ed(2)
	before := load(t, first+" old label\n"+second)
	after := load(t, "# new heading\n"+second+"\n"+first+" new label")
	if diff := Compare(before, after); diff.Changed || len(diff.Changes) != 0 {
		t.Fatal(diff)
	}
	caseOnly := load(t, strings.Replace(first, "restrict,command", "RESTRICT,COMMAND", 1)+"\n"+second)
	if Compare(before, caseOnly).Changed {
		t.Fatal("option keyword case should not drift")
	}
}

func TestDiffMultiplicityAndOptionChanges(t *testing.T) {
	key := "ssh-ed25519 " + ed(7)
	before := load(t, "restrict "+key+"\n"+key)
	for _, text := range []string{key, "restrict " + key + "\nrestrict " + key, "command=\"run\" " + key + "\n" + key, "restrict " + key + "\n" + key + "\n" + key} {
		diff := Compare(before, load(t, text))
		if !diff.Changed || len(diff.Changes) != 1 || diff.Changes[0].Kind != "authorization-changed" || len(diff.Changes[0].Before) != 2 {
			t.Fatal(diff)
		}
	}
	// Ordered options remain observable: restrict and its later overrides matter.
	a := load(t, "restrict,pty "+key)
	b := load(t, "pty,restrict "+key)
	if !Compare(a, b).Changed {
		t.Fatal("collapsed ordered options")
	}
}

func TestDiffAdditionRemovalAndStableJSON(t *testing.T) {
	a := load(t, "ssh-ed25519 "+ed(7))
	b := load(t, "ssh-ed25519 "+ed(2))
	diff := Compare(a, b)
	if !diff.Changed || len(diff.Changes) != 2 {
		t.Fatal(diff)
	}
	kinds := map[string]bool{}
	for _, change := range diff.Changes {
		kinds[change.Kind] = true
	}
	if !kinds["key-added"] || !kinds["key-removed"] {
		t.Fatal(diff)
	}
	first, _ := json.Marshal(diff)
	for i := 0; i < 20; i++ {
		current, _ := json.Marshal(Compare(a, b))
		if string(first) != string(current) {
			t.Fatal("unstable JSON")
		}
	}
	if Compare(load(t, ""), load(t, "")).Changed {
		t.Fatal("empty inventories differ")
	}
}
