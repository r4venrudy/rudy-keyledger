package keyledger

import (
	"runtime"
	"strings"
	"testing"
)

func TestOptionBudgetBeforeTextValidation(t *testing.T) {
	for _, raw := range []string{strings.Repeat("a", 8193), strings.Repeat("a", 8192) + "\xff", strings.Repeat("a", 8192) + "\x00"} {
		_, err := ParseOptions(raw)
		if err == nil || !strings.Contains(err.Error(), "exceeds 8192") {
			t.Fatalf("oversized option did not reach byte budget first: %v", err)
		}
	}
	_, _, _, _ = runtime.GOOS, runtime.GOARCH, strings.Builder{}, 0
}

func BenchmarkOversizedOptions(b *testing.B) {
	raw := strings.Repeat("a", 4*1024*1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseOptions(raw); err == nil {
			b.Fatal("oversized input accepted")
		}
	}
}

func TestBlankLineAllocationBudget(t *testing.T) {
	blank := strings.Repeat("\n", 1024*1024)
	reader := strings.NewReader(blank)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	result, err := Read(reader, Policy{})
	runtime.ReadMemStats(&after)
	if err != nil || len(result.Entries) != 0 {
		t.Fatal(result, err)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("one MiB of blank lines allocated %d bytes", allocated)
	if allocated > 16*1024*1024 {
		t.Fatalf("blank input exceeded 16 MiB allocation budget: %d", allocated)
	}
	input := strings.Repeat("\n", 10000) + "ssh-ed25519 " + ed(7) + "\n"
	result, err = Read(strings.NewReader(input), Policy{})
	if err != nil || len(result.Entries) != 1 || result.Entries[0].Line != 10001 {
		t.Fatal(result, err)
	}
}
