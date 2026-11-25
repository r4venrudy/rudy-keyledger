// Package keyledger inventories supported authorized_keys records offline.
package keyledger

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Key describes public key material, without retaining its encoded blob.
type Key struct {
	Algorithm   string `json:"algorithm"`
	Bits        int    `json:"bits"`
	Fingerprint string `json:"fingerprint"`
}

type wire struct{ data []byte }

func (w *wire) field() ([]byte, error) {
	if len(w.data) < 4 {
		return nil, errors.New("truncated SSH string length")
	}
	n := uint64(binary.BigEndian.Uint32(w.data))
	w.data = w.data[4:]
	if n > uint64(len(w.data)) {
		return nil, errors.New("truncated SSH string payload")
	}
	value := w.data[:int(n)]
	w.data = w.data[int(n):]
	return value, nil
}

func positiveMP(w *wire) (*big.Int, error) {
	p, err := w.field()
	if err != nil {
		return nil, err
	}
	if len(p) == 0 || p[0]&0x80 != 0 || (len(p) > 1 && p[0] == 0 && p[1]&0x80 == 0) {
		return nil, errors.New("RSA integer is not canonical and positive")
	}
	n := new(big.Int).SetBytes(p)
	if n.Sign() <= 0 {
		return nil, errors.New("RSA integer must be positive")
	}
	return n, nil
}

// DecodeKey validates the SSH wire layout and supported public parameters.
// It does not establish possession of a private key or test Ed25519 subgroup membership.
func DecodeKey(algorithm, encoded string) (Key, error) {
	key := Key{Algorithm: algorithm}
	if len(encoded) > 8192 || strings.ContainsAny(encoded, "\r\n \t") {
		return key, errors.New("invalid or oversized base64 key")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		// OpenSSH public keys also commonly omit terminal padding.
		data, err = base64.RawStdEncoding.Strict().DecodeString(encoded)
	}
	if err != nil {
		return key, errors.New("invalid base64 key")
	}
	w := wire{data}
	name, err := w.field()
	if err != nil || string(name) != algorithm {
		return key, errors.New("key algorithm disagrees with SSH wire blob")
	}
	switch algorithm {
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com":
		public, err := w.field()
		if err != nil || len(public) != 32 {
			return key, errors.New("Ed25519 public key must contain 32 bytes")
		}
		if algorithm == "sk-ssh-ed25519@openssh.com" {
			if err := securityApplication(&w); err != nil {
				return key, err
			}
		}
		key.Bits = 256
	case "ssh-rsa":
		e, err := positiveMP(&w)
		if err != nil {
			return key, fmt.Errorf("RSA exponent: %w", err)
		}
		n, err := positiveMP(&w)
		if err != nil {
			return key, fmt.Errorf("RSA modulus: %w", err)
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 2147483647 || e.Bit(0) == 0 {
			return key, errors.New("RSA exponent must be odd, between 3 and 2147483647")
		}
		key.Bits = n.BitLen()
		if key.Bits < 1024 || key.Bits > 16384 || n.Bit(0) == 0 || e.Cmp(n) >= 0 {
			return key, errors.New("RSA modulus outside supported 1024..16384-bit odd profile")
		}
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ecdsa-sha2-nistp256@openssh.com":
		curveName, err := w.field()
		if err != nil || string(curveName) != strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(algorithm, "sk-"), "ecdsa-sha2-"), "@openssh.com") {
			return key, errors.New("ECDSA curve name disagrees with algorithm")
		}
		curves := map[string]elliptic.Curve{"nistp256": elliptic.P256(), "nistp384": elliptic.P384(), "nistp521": elliptic.P521()}
		curve := curves[string(curveName)]
		point, err := w.field()
		if err != nil {
			return key, err
		}
		x, y := elliptic.Unmarshal(curve, point)
		if x == nil || y == nil {
			return key, errors.New("ECDSA point must be an uncompressed point on the named curve")
		}
		if algorithm == "sk-ecdsa-sha2-nistp256@openssh.com" {
			if err := securityApplication(&w); err != nil {
				return key, err
			}
		}
		key.Bits = curve.Params().BitSize
	default:
		return key, errors.New("unsupported key algorithm (certificates and hybrid keys are outside this preview)")
	}
	if len(w.data) != 0 {
		return key, errors.New("trailing bytes in SSH key blob")
	}
	digest := sha256.Sum256(data)
	key.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	return key, nil
}

// OpenSSH serializes the application as a NUL-free SSH cstring. It remains
// opaque binary metadata included in the fingerprint, not rendered as text.
func securityApplication(w *wire) error {
	value, err := w.field()
	if err != nil {
		return err
	}
	if bytes.IndexByte(value, 0) >= 0 {
		return errors.New("security-key application contains NUL")
	}
	return nil
}
