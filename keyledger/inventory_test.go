package keyledger

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func load(t *testing.T, text string) Inventory {
	t.Helper()
	result, err := Read(strings.NewReader(text), Policy{})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestInventoryCommentsAndDuplicates(t *testing.T) {
	text := "# test\r\n\t\r\nrestrict,command=\"hello world\" ssh-ed25519 " + ed(7) + " label with spaces\r\nssh-ed25519 " + ed(7) + " duplicate\n"
	result := load(t, text)
	if len(result.Entries) != 2 || result.Entries[0].Line != 3 || result.Entries[0].Comment != "label with spaces" || len(result.Issues) != 1 || result.Issues[0].Code != "duplicate-key" {
		t.Fatal(result)
	}
	if len(load(t, "# no keys").Entries) != 0 {
		t.Fatal("empty inventory")
	}
}

func TestInventoryRejectsMalformedRecords(t *testing.T) {
	for _, text := range []string{"ssh-ed25519", "ssh-ed25519 !", "restrict, ssh-ed25519 " + ed(7), "ssh-dss AAAA", "\ufeff# bom", "# bad\x00", "# bad\r", string([]byte{0xff}), "#" + strings.Repeat("a", MaxLineBytes), strings.Repeat("#", MaxInputBytes+1)} {
		if result, err := Read(strings.NewReader(text), Policy{}); err == nil || result.Schema != "" {
			t.Fatal("accepted invalid input or leaked partial report", len(text), err)
		}
	}
	line := "ssh-ed25519 " + ed(7) + "\n"
	if _, err := Read(strings.NewReader(strings.Repeat(line, MaxEntries+1)), Policy{}); err == nil {
		t.Fatal("key count budget")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("fixture read failure") }

func TestReadError(t *testing.T) {
	if _, err := Read(io.MultiReader(strings.NewReader("# partial"), errorReader{}), Policy{}); err == nil {
		t.Fatal("read error ignored")
	}
}

func TestPolicyFindings(t *testing.T) {
	input := "cert-authority,future-flag,command ssh-ed25519 " + ed(7)
	result, err := Read(strings.NewReader(input), Policy{RequireRestrict: true, ForbidCA: true})
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]bool{}
	for _, issue := range result.Issues {
		codes[issue.Code] = true
	}
	for _, code := range []string{"ca-forbidden", "unknown-option", "option-shape", "restrict-required"} {
		if !codes[code] {
			t.Fatal(code, result)
		}
	}
	result, err = Read(strings.NewReader("RESTRICT ssh-ed25519 "+ed(7)), Policy{RequireRestrict: true})
	if err != nil || len(result.Issues) != 0 {
		t.Fatal(result, err)
	}
}

func FuzzRead(f *testing.F) {
	f.Add("ssh-ed25519 " + ed(7))
	f.Add("restrict,command=\"hello world\" ssh-ed25519 " + ed(2))
	f.Fuzz(func(t *testing.T, data string) {
		result, err := Read(strings.NewReader(data), Policy{})
		if err != nil && result.Schema != "" {
			t.Fatal("partial result on error")
		}
	})
}
