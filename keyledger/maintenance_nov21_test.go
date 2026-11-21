package keyledger

import (
	"io"
	"strings"
	"testing"
)

type policyReader struct{ calls int }

func (reader *policyReader) Read([]byte) (int, error) { reader.calls++; return 0, io.EOF }

func TestLibraryPolicyBounds(t *testing.T) {
	for _, minimum := range []int{-1, 1, 1023, 16385} {
		reader := &policyReader{}
		result, err := Read(reader, Policy{MinRSABits: minimum})
		if err == nil || !strings.Contains(err.Error(), "MinRSABits") || result.Schema != "" || reader.calls != 0 {
			t.Fatalf("invalid policy read input or returned success: minimum=%d calls=%d err=%v", minimum, reader.calls, err)
		}
	}
	for _, minimum := range []int{0, 1024, 2048, 16384} {
		if _, err := Read(strings.NewReader(""), Policy{MinRSABits: minimum}); err != nil {
			t.Fatal(minimum, err)
		}
	}
}

func TestPublicOptionParserTextProfile(t *testing.T) {
	for _, value := range []string{"nul\x00hidden", "new\nline", "carriage\rreturn", "delete\x7f", "c1\u0085", string([]byte{0xff})} {
		if options, err := ParseOptions("command=\"" + value + "\""); err == nil || options != nil {
			t.Fatalf("accepted unsafe option value: %q", value)
		}
	}
	for _, raw := range []string{"", "restrict", "command=\"tab\tinside\"", "command=\"日本語\""} {
		if _, err := ParseOptions(raw); err != nil {
			t.Fatal(raw, err)
		}
	}
}
