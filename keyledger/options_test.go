package keyledger

import (
	"reflect"
	"strings"
	"testing"
)

func TestQuotedOptions(t *testing.T) {
	raw := `restrict,command="printf \"hello, user\" C:\path",permitopen="host:80",permitopen="[::1]:22"`
	field, rest, err := firstField(raw + "\tssh-ed25519 payload comment")
	if err != nil || field != raw || rest != "ssh-ed25519 payload comment" {
		t.Fatal(field, rest, err)
	}
	options, err := ParseOptions(field)
	if err != nil || len(options) != 4 || options[0].Value != nil || *options[1].Value != `printf "hello, user" C:\path` {
		t.Fatal(options, err)
	}
	if *options[2].Value != "host:80" || *options[3].Value != "[::1]:22" {
		t.Fatal(options)
	}
	a, _ := ParseOptions(`ReStRiCt,COMMAND=""`)
	b, _ := ParseOptions(`restrict,command=""`)
	if !reflect.DeepEqual(a, b) {
		t.Fatal(a, b)
	}
	c, _ := ParseOptions("restrict,command")
	if optionSignature(a) == optionSignature(c) {
		t.Fatal("empty value collapsed into bare flag")
	}
}

func TestInvalidOptions(t *testing.T) {
	for _, raw := range []string{",restrict", "restrict,", "a,,b", `command=plain`, `command="unterminated`, `command="ok"junk`, "restrict command", "a/b", strings.Repeat("a,", 128) + "b", strings.Repeat("a", 8193)} {
		if _, err := ParseOptions(raw); err == nil {
			t.Fatal("accepted invalid options", raw)
		}
	}
	if _, _, err := firstField(`command="bad key`); err == nil {
		t.Fatal("unterminated field")
	}
}

func FuzzOptions(f *testing.F) {
	f.Add(`restrict,command="hello, world"`)
	f.Add(`command="quoted \"value\""`)
	f.Fuzz(func(t *testing.T, raw string) {
		options, err := ParseOptions(raw)
		if err == nil && len(options) > 128 {
			t.Fatal("option budget")
		}
		_, _, _ = firstField(raw)
	})
}
