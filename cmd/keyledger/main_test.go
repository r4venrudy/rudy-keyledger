package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

const public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH fixture"

func TestCLIExitContracts(t *testing.T) {
	for _, test := range []struct {
		args  []string
		input string
		code  int
	}{
		{[]string{"--version"}, "", 0}, {[]string{"--help"}, "", 0}, {[]string{"bad"}, "", 2},
		{[]string{"inspect", "--input", "-", "--format", "json"}, public, 0},
		{[]string{"inspect", "--input", "-", "--format", "json", "--require-restrict", "--fail-on-warning"}, public, 1},
		{[]string{"inspect", "--input", "-", "--format", "xml"}, public, 2},
		{[]string{"inspect", "--input", "-", "--min-rsa-bits", "2"}, public, 2},
		{[]string{"inspect", "--input", "-"}, "ssh-ed25519 !", 2},
		{[]string{"inspect"}, "", 2}, {[]string{"inspect", "extra"}, "", 2},
		{[]string{"diff", "--before", "-", "--after", "-"}, public, 2},
	} {
		var out, diagnostics bytes.Buffer
		code := run(test.args, strings.NewReader(test.input), &out, &diagnostics)
		if code != test.code {
			t.Fatal(test.args, code, test.code, out.String(), diagnostics.String())
		}
		if code == 2 && out.Len() != 0 {
			t.Fatal("invalid request emitted a success report")
		}
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("fixture write failure") }

func TestOutputErrors(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"--help"}, {"inspect", "--input", "-"}, {"inspect", "--input", "-", "--format", "json"}} {
		if code := run(args, strings.NewReader(public), brokenWriter{}, io.Discard); code != 2 {
			t.Fatal(args, code)
		}
	}
}
