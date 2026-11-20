package keyledger

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"testing"
)

func pack(parts ...[]byte) []byte {
	var result bytes.Buffer
	for _, part := range parts {
		_ = binary.Write(&result, binary.BigEndian, uint32(len(part)))
		result.Write(part)
	}
	return result.Bytes()
}

func encoded(parts ...[]byte) string { return base64.StdEncoding.EncodeToString(pack(parts...)) }
func ed(seed byte) string {
	return encoded([]byte("ssh-ed25519"), bytes.Repeat([]byte{seed}, 32))
}

func TestEd25519WireAndFingerprint(t *testing.T) {
	blob := pack([]byte("ssh-ed25519"), bytes.Repeat([]byte{7}, 32))
	digest := sha256.Sum256(blob)
	key, err := DecodeKey("ssh-ed25519", base64.StdEncoding.EncodeToString(blob))
	if err != nil || key.Bits != 256 || key.Fingerprint != "SHA256:"+base64.RawStdEncoding.EncodeToString(digest[:]) {
		t.Fatal(key, err)
	}
	if _, err := DecodeKey("ssh-ed25519", base64.RawStdEncoding.EncodeToString(blob)); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, blob[:3], blob[:len(blob)-1], append(append([]byte{}, blob...), 0), pack([]byte("ssh-rsa")), pack([]byte("ssh-ed25519"), make([]byte, 31))} {
		if _, err := DecodeKey("ssh-ed25519", base64.StdEncoding.EncodeToString(data)); err == nil {
			t.Fatalf("accepted malformed blob %x", data)
		}
	}
	for _, bad := range []string{"!", ed(7) + "\n", ed(7) + "=", "AAAA\t"} {
		if _, err := DecodeKey("ssh-ed25519", bad); err == nil {
			t.Fatal("accepted malformed base64", bad)
		}
	}
}

func TestECDSACurves(t *testing.T) {
	for name, curve := range map[string]elliptic.Curve{"nistp256": elliptic.P256(), "nistp384": elliptic.P384(), "nistp521": elliptic.P521()} {
		algorithm := "ecdsa-sha2-" + name
		point := elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy)
		key, err := DecodeKey(algorithm, encoded([]byte(algorithm), []byte(name), point))
		if err != nil || key.Bits != curve.Params().BitSize {
			t.Fatal(key, err)
		}
		point[len(point)-1] ^= 1
		for _, value := range []string{encoded([]byte(algorithm), []byte(name), point), encoded([]byte(algorithm), []byte("wrong"), point)} {
			if _, err := DecodeKey(algorithm, value); err == nil {
				t.Fatal("accepted invalid ECDSA point or curve")
			}
		}
	}
}

func TestRSAPublicParameters(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	n := append([]byte{0}, private.N.Bytes()...)
	value := encoded([]byte("ssh-rsa"), big.NewInt(int64(private.E)).Bytes(), n)
	key, err := DecodeKey("ssh-rsa", value)
	if err != nil || key.Bits != 1024 {
		t.Fatal(key, err)
	}
	for _, exponent := range [][]byte{nil, {0}, {2}, {0, 3}, {0x80}, {1, 0, 0, 0, 1}} {
		if _, err := DecodeKey("ssh-rsa", encoded([]byte("ssh-rsa"), exponent, n)); err == nil {
			t.Fatal("accepted invalid exponent", exponent)
		}
	}
	for _, modulus := range [][]byte{{3}, {0, 3}, n[1:], append([]byte{0}, n...)} {
		if _, err := DecodeKey("ssh-rsa", encoded([]byte("ssh-rsa"), []byte{3}, modulus)); err == nil {
			t.Fatal("accepted invalid modulus")
		}
	}
}

func FuzzDecodeKey(f *testing.F) {
	f.Add("ssh-ed25519", ed(7))
	f.Add("ssh-rsa", "AAAA")
	f.Fuzz(func(t *testing.T, algorithm, data string) {
		key, err := DecodeKey(algorithm, data)
		if err == nil && (key.Bits <= 0 || len(key.Fingerprint) != 50) {
			t.Fatal(key)
		}
	})
}
