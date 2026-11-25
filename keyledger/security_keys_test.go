package keyledger

import (
	"bytes"
	"crypto/elliptic"
	"strings"
	"testing"
)

var _ = elliptic.P256
var _ = strings.NewReader

func TestSecurityKey0(t *testing.T) {
	algorithm := "sk-ssh-ed25519@openssh.com"
	key, err := DecodeKey(algorithm, encoded([]byte(algorithm), bytes.Repeat([]byte{7}, 32), []byte("ssh:")))
	if err != nil || key.Bits != 256 {
		t.Fatal(key, err)
	}
	other, err := DecodeKey(algorithm, encoded([]byte(algorithm), bytes.Repeat([]byte{7}, 32), []byte("ssh:other")))
	if err != nil || other.Fingerprint == key.Fingerprint {
		t.Fatal("application must participate in identity", other, err)
	}
	for _, app := range [][]byte{nil, []byte("ssh:"), {0xff}} {
		if _, err := DecodeKey(algorithm, encoded([]byte(algorithm), bytes.Repeat([]byte{7}, 32), app)); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{encoded([]byte(algorithm), bytes.Repeat([]byte{7}, 32)), encoded([]byte(algorithm), bytes.Repeat([]byte{7}, 32), []byte("bad\x00app")), encoded([]byte(algorithm), bytes.Repeat([]byte{7}, 32), []byte("ssh:"), nil)} {
		if _, err := DecodeKey(algorithm, bad); err == nil {
			t.Fatal("malformed security key accepted")
		}
	}
	line := algorithm + " " + encoded([]byte(algorithm), bytes.Repeat([]byte{7}, 32), []byte("ssh:"))
	inventory, err := Read(strings.NewReader(line), Policy{})
	if err != nil || len(inventory.Entries) != 1 || len(inventory.Issues) != 0 {
		t.Fatal(inventory, err)
	}
	reordered, err := Read(strings.NewReader(line+" comment"), Policy{})
	if err != nil || Compare(inventory, reordered).Changed {
		t.Fatal("comment changed identity", err)
	}
}
