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

func TestSecurityKey1(t *testing.T) {
	algorithm := "sk-ecdsa-sha2-nistp256@openssh.com"
	key, err := DecodeKey(algorithm, encoded([]byte(algorithm), []byte("nistp256"), elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy), []byte("ssh:")))
	if err != nil || key.Bits != 256 {
		t.Fatal(key, err)
	}
	other, err := DecodeKey(algorithm, encoded([]byte(algorithm), []byte("nistp256"), elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy), []byte("ssh:other")))
	if err != nil || other.Fingerprint == key.Fingerprint {
		t.Fatal("application must participate in identity", other, err)
	}
	for _, app := range [][]byte{nil, []byte("ssh:"), {0xff}} {
		if _, err := DecodeKey(algorithm, encoded([]byte(algorithm), []byte("nistp256"), elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy), app)); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{encoded([]byte(algorithm), []byte("nistp256"), elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)), encoded([]byte(algorithm), []byte("nistp256"), elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy), []byte("bad\x00app")), encoded([]byte(algorithm), []byte("nistp256"), elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy), []byte("ssh:"), nil)} {
		if _, err := DecodeKey(algorithm, bad); err == nil {
			t.Fatal("malformed security key accepted")
		}
	}
	line := algorithm + " " + encoded([]byte(algorithm), []byte("nistp256"), elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy), []byte("ssh:"))
	inventory, err := Read(strings.NewReader(line), Policy{})
	if err != nil || len(inventory.Entries) != 1 || len(inventory.Issues) != 0 {
		t.Fatal(inventory, err)
	}
	reordered, err := Read(strings.NewReader(line+" comment"), Policy{})
	if err != nil || Compare(inventory, reordered).Changed {
		t.Fatal("comment changed identity", err)
	}
}

func TestSecurityECDSAMalformedPoint(t *testing.T) {
	algorithm := "sk-ecdsa-sha2-nistp256@openssh.com"
	for _, curve := range []string{"nistp256", "nistp384"} {
		if _, err := DecodeKey(algorithm, encoded([]byte(algorithm), []byte(curve), bytes.Repeat([]byte{4}, 65), []byte("ssh:"))); err == nil {
			t.Fatal("bad point accepted")
		}
	}
}

func TestSecurityVerificationPolicy(t *testing.T) {
	algorithm := "sk-ssh-ed25519@openssh.com"
	line := algorithm + " " + encoded([]byte(algorithm), bytes.Repeat([]byte{7}, 32), []byte("ssh:"))
	result, err := Read(strings.NewReader(line), Policy{RequireUserVerification: true})
	if err != nil || len(result.Issues) != 1 || result.Issues[0].Code != "sk-verification-required" {
		t.Fatal(result, err)
	}
	for _, prefix := range []string{"verify-required ", "VERIFY-REQUIRED,restrict "} {
		result, err = Read(strings.NewReader(prefix+line), Policy{RequireUserVerification: true})
		if err != nil || len(result.Issues) != 0 {
			t.Fatal(result, err)
		}
	}
	result, err = Read(strings.NewReader("verify-required=\"yes\" "+line), Policy{RequireUserVerification: true})
	if err != nil || len(result.Issues) != 2 {
		t.Fatal(result, err)
	}
	result, err = Read(strings.NewReader("ssh-ed25519 "+ed(7)), Policy{RequireUserVerification: true})
	if err != nil || len(result.Issues) != 0 {
		t.Fatal(result, err)
	}
	result, err = Read(strings.NewReader(line+"\nverify-required "+line), Policy{RequireUserVerification: true})
	if err != nil || len(result.Issues) != 2 {
		t.Fatal(result, err)
	}
}
