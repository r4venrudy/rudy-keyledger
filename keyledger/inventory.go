package keyledger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const MaxInputBytes = 8 * 1024 * 1024
const MaxLineBytes = 8192
const MaxEntries = 16384

type Entry struct {
	Key
	Line    int      `json:"line"`
	Options []Option `json:"options"`
	Comment string   `json:"comment,omitempty"`
}

type Issue struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Line        int    `json:"line"`
	Fingerprint string `json:"fingerprint"`
	Message     string `json:"message"`
}

type Policy struct {
	MinRSABits      int
	RequireRestrict bool
	ForbidCA        bool
}

type Inventory struct {
	Schema  string  `json:"schema"`
	Entries []Entry `json:"entries"`
	Issues  []Issue `json:"issues"`
}

// Read parses a bounded UTF-8 authorized_keys file without executing commands or
// consulting the network. Invalid and unsupported records fail the entire read.
func Read(reader io.Reader, policy Policy) (Inventory, error) {
	if policy.MinRSABits != 0 && (policy.MinRSABits < 1024 || policy.MinRSABits > 16384) {
		return Inventory{}, errors.New("MinRSABits must be zero (default) or between 1024 and 16384")
	}
	result := Inventory{Schema: "rudy.keyledger.inventory/v1", Entries: []Entry{}, Issues: []Issue{}}
	data, err := io.ReadAll(io.LimitReader(reader, MaxInputBytes+1))
	if err != nil {
		return Inventory{}, fmt.Errorf("read input: %w", err)
	}
	if len(data) > MaxInputBytes {
		return Inventory{}, errors.New("input exceeds 8 MiB")
	}
	if !utf8.Valid(data) {
		return Inventory{}, errors.New("input must be UTF-8")
	}
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return Inventory{}, errors.New("UTF-8 BOM is outside the authorized_keys preview profile")
	}
	lineNumber := 0
	for raw := range strings.SplitSeq(string(data), "\n") {
		lineNumber++
		if len(raw) > MaxLineBytes {
			return Inventory{}, fmt.Errorf("line %d exceeds 8192 bytes", lineNumber)
		}
		for _, c := range raw {
			if (c < 32 && c != '\t') || (c >= 0x7f && c <= 0x9f) {
				return Inventory{}, fmt.Errorf("line %d contains a control character", lineNumber)
			}
		}
		line := strings.Trim(raw, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(result.Entries) >= MaxEntries {
			return Inventory{}, errors.New("more than 16384 key entries")
		}
		entry, err := parseEntry(line)
		if err != nil {
			return Inventory{}, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		entry.Line = lineNumber
		result.Entries = append(result.Entries, entry)
	}
	result.Issues = review(result.Entries, policy)
	return result, nil
}

func keyToken(token string) bool {
	return strings.HasPrefix(token, "ssh-") || strings.HasPrefix(token, "ecdsa-") || strings.HasPrefix(token, "sk-")
}

func parseEntry(line string) (Entry, error) {
	first, rest, err := firstField(line)
	if err != nil {
		return Entry{}, err
	}
	options := []Option{}
	algorithm := first
	if !keyToken(first) {
		options, err = ParseOptions(first)
		if err != nil {
			return Entry{}, err
		}
		algorithm, rest, err = firstField(rest)
		if err != nil {
			return Entry{}, err
		}
	}
	blob, comment, err := firstField(rest)
	if err != nil || blob == "" {
		return Entry{}, errors.New("missing public key blob")
	}
	key, err := DecodeKey(algorithm, blob)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Key: key, Options: options, Comment: comment}, nil
}

var flagOptions = map[string]bool{
	"restrict": true, "cert-authority": true, "agent-forwarding": true, "no-agent-forwarding": true,
	"port-forwarding": true, "no-port-forwarding": true, "pty": true, "no-pty": true,
	"user-rc": true, "no-user-rc": true, "x11-forwarding": true, "no-x11-forwarding": true,
	"touch-required": true, "no-touch-required": true, "verify-required": true, "no-verify-required": true,
}
var valueOptions = map[string]bool{
	"command": true, "from": true, "environment": true, "permitopen": true,
	"permitlisten": true, "principals": true, "tunnel": true, "expiry-time": true,
}

func review(entries []Entry, policy Policy) []Issue {
	issues := []Issue{}
	seen := map[string]int{}
	minimum := policy.MinRSABits
	if minimum == 0 {
		minimum = 2048
	}
	for _, entry := range entries {
		add := func(code, message string) {
			issues = append(issues, Issue{code, "warning", entry.Line, entry.Fingerprint, message})
		}
		if entry.Algorithm == "ssh-rsa" && entry.Bits < minimum {
			add("rsa-size", fmt.Sprintf("RSA key has %d bits, below policy minimum %d", entry.Bits, minimum))
		}
		if previous, ok := seen[entry.Fingerprint]; ok {
			add("duplicate-key", fmt.Sprintf("same public key also appears at line %d; each option set is retained", previous))
		} else {
			seen[entry.Fingerprint] = entry.Line
		}
		restricted := false
		singletons := map[string]bool{}
		for _, option := range entry.Options {
			if option.Value != nil && (option.Name == "command" || option.Name == "from" || option.Name == "principals") {
				if singletons[option.Name] {
					add("repeated-option", "OpenSSH rejects repeated clauses for option: "+option.Name)
				}
				singletons[option.Name] = true
			}
			if !flagOptions[option.Name] && !valueOptions[option.Name] {
				add("unknown-option", "option is outside this preview's known option list: "+option.Name)
			}
			if (flagOptions[option.Name] && option.Value != nil) || (valueOptions[option.Name] && option.Value == nil) {
				add("option-shape", "option has an unexpected value form: "+option.Name)
			}
			restricted = restricted || (option.Name == "restrict" && option.Value == nil)
			if policy.ForbidCA && option.Name == "cert-authority" {
				add("ca-forbidden", "certificate-authority authorization is disallowed by policy")
			}
		}
		if policy.RequireRestrict && !restricted {
			add("restrict-required", "policy requires an explicit restrict flag; other restrictions are not inferred")
		}
	}
	return issues
}
