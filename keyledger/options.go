package keyledger

import (
	"errors"
	"strings"
)

// Option retains order and repeated values. Names are case-insensitive in OpenSSH.
// Value is nil for a bare flag and points to the decoded string for name="value".
type Option struct {
	Name  string  `json:"name"`
	Value *string `json:"value,omitempty"`
}

// firstField recognizes spaces inside quoted authorized_keys option values.
// Only backslash followed by a double quote escapes a quote, as in OpenSSH.
func firstField(line string) (field, rest string, err error) {
	quoted := false
	for i := 0; i < len(line); i++ {
		if quoted && line[i] == '\\' && i+1 < len(line) && line[i+1] == '"' {
			i++
			continue
		}
		if line[i] == '"' {
			quoted = !quoted
		}
		if !quoted && (line[i] == ' ' || line[i] == '\t') {
			return line[:i], strings.TrimLeft(line[i:], " \t"), nil
		}
	}
	if quoted {
		return "", "", errors.New("unterminated quoted option")
	}
	return line, "", nil
}

// ParseOptions checks the authorized_keys option grammar. Semantic checks on
// option values (host patterns, command execution, expiry times) belong to sshd.
func ParseOptions(raw string) ([]Option, error) {
	if raw == "" {
		return []Option{}, nil
	}
	if len(raw) > 8192 {
		return nil, errors.New("option field exceeds 8192 bytes")
	}
	result := []Option{}
	for len(raw) > 0 {
		if len(result) >= 128 {
			return nil, errors.New("more than 128 options on one key")
		}
		i := 0
		for i < len(raw) && ((raw[i] >= 'a' && raw[i] <= 'z') || (raw[i] >= 'A' && raw[i] <= 'Z') || (raw[i] >= '0' && raw[i] <= '9') || raw[i] == '-') {
			i++
		}
		if i == 0 {
			return nil, errors.New("missing option name")
		}
		option := Option{Name: strings.ToLower(raw[:i])}
		raw = raw[i:]
		if strings.HasPrefix(raw, "=") {
			raw = raw[1:]
			if !strings.HasPrefix(raw, "\"") {
				return nil, errors.New("option values must be double-quoted")
			}
			raw = raw[1:]
			var value strings.Builder
			i = 0
			for i < len(raw) && raw[i] != '"' {
				if raw[i] == '\\' && i+1 < len(raw) && raw[i+1] == '"' {
					i++
				}
				value.WriteByte(raw[i])
				i++
			}
			if i == len(raw) {
				return nil, errors.New("unterminated quoted option value")
			}
			decoded := value.String()
			option.Value = &decoded
			raw = raw[i+1:]
		}
		result = append(result, option)
		if len(raw) == 0 {
			break
		}
		if raw[0] != ',' {
			return nil, errors.New("expected comma between options")
		}
		raw = raw[1:]
		if len(raw) == 0 {
			return nil, errors.New("trailing option comma")
		}
	}
	return result, nil
}

// optionSignature is unambiguous even when values contain delimiters.
func optionSignature(options []Option) string {
	var value strings.Builder
	for _, option := range options {
		value.WriteString(option.Name)
		value.WriteByte(0)
		if option.Value != nil {
			value.WriteByte('=')
			value.WriteString(*option.Value)
		}
		value.WriteByte(0)
	}
	return value.String()
}
