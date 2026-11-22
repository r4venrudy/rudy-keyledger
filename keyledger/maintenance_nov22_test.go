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
