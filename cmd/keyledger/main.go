package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/r4venrudy/rudy-keyledger/keyledger"
)

const version = "0.1.0-preview"

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(err error) int { fmt.Fprintln(stderr, "keyledger:", err); return 2 }
	if len(args) == 1 && args[0] == "--version" {
		_, err := fmt.Fprintln(stdout, "keyledger "+version)
		if err != nil {
			return fail(err)
		}
		return 0
	}
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		_, err := fmt.Fprintln(stdout, "KeyLedger — offline SSH access inventory and drift checks\n\nkeyledger inspect --input authorized_keys [--format json] [--fail-on-warning]\nkeyledger diff --before old_keys --after new_keys [--format json]\n\nPolicy: --min-rsa-bits 2048 --require-restrict --forbid-ca\nUse - as one input path for stdin. Exit 0: clear; 1: drift/policy gate; 2: invalid input.")
		if err != nil {
			return fail(err)
		}
		return 0
	}
	command := args[0]
	if command != "inspect" && command != "diff" {
		return fail(errors.New("expected inspect or diff; see --help"))
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "text or json")
	minimum := flags.Int("min-rsa-bits", 2048, "minimum RSA size for warnings")
	restrict := flags.Bool("require-restrict", false, "require explicit restrict flag")
	forbidCA := flags.Bool("forbid-ca", false, "warn on cert-authority records")
	gate := flags.Bool("fail-on-warning", false, "exit 1 for any policy warning")
	var input, before, after string
	if command == "inspect" {
		flags.StringVar(&input, "input", "", "authorized_keys file or -")
	} else {
		flags.StringVar(&before, "before", "", "previous authorized_keys file or -")
		flags.StringVar(&after, "after", "", "next authorized_keys file or -")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments"))
	}
	if *format != "text" && *format != "json" {
		return fail(errors.New("format must be text or json"))
	}
	if *minimum < 1024 || *minimum > 16384 {
		return fail(errors.New("min-rsa-bits must be between 1024 and 16384"))
	}
	policy := keyledger.Policy{MinRSABits: *minimum, RequireRestrict: *restrict, ForbidCA: *forbidCA}
	read := func(path string) (keyledger.Inventory, error) {
		if path == "" {
			return keyledger.Inventory{}, errors.New("an explicit input path is required")
		}
		if path == "-" {
			return keyledger.Read(stdin, policy)
		}
		info, err := os.Stat(path)
		if err != nil {
			return keyledger.Inventory{}, err
		}
		if !info.Mode().IsRegular() {
			return keyledger.Inventory{}, errors.New("input must be a regular file or stdin")
		}
		file, err := os.Open(path)
		if err != nil {
			return keyledger.Inventory{}, err
		}
		defer file.Close()
		return keyledger.Read(file, policy)
	}
	emit := func(value any) error {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	}
	if command == "inspect" {
		inventory, err := read(input)
		if err != nil {
			return fail(err)
		}
		if *format == "json" {
			err = emit(inventory)
		} else {
			err = printInventory(stdout, inventory)
		}
		if err != nil {
			return fail(err)
		}
		if *gate && len(inventory.Issues) != 0 {
			return 1
		}
		return 0
	}
	if before == "-" && after == "-" {
		return fail(errors.New("only one diff input may use stdin"))
	}
	old, err := read(before)
	if err != nil {
		return fail(err)
	}
	next, err := read(after)
	if err != nil {
		return fail(err)
	}
	diff := keyledger.Compare(old, next)
	report := struct {
		keyledger.Difference
		BeforeIssues []keyledger.Issue `json:"before_issues"`
		AfterIssues  []keyledger.Issue `json:"after_issues"`
	}{diff, old.Issues, next.Issues}
	if *format == "json" {
		err = emit(report)
	} else {
		_, err = fmt.Fprintf(stdout, "SSH access drift: %t | entries %d -> %d | changed keys %d\n", diff.Changed, diff.BeforeCount, diff.AfterCount, len(diff.Changes))
		for _, change := range diff.Changes {
			if err == nil {
				_, err = fmt.Fprintf(stdout, "%s  %s  records %d -> %d\n", change.Kind, change.Fingerprint, len(change.Before), len(change.After))
			}
		}
		if err == nil && len(next.Issues) > 0 {
			err = printInventory(stdout, next)
		}
	}
	if err != nil {
		return fail(err)
	}
	// The deployment gate evaluates the prospective file; old warnings are evidence.
	if diff.Changed || (*gate && len(next.Issues) > 0) {
		return 1
	}
	return 0
}

func printInventory(output io.Writer, inventory keyledger.Inventory) error {
	if _, err := fmt.Fprintf(output, "SSH access inventory: %d records, %d policy warnings\n", len(inventory.Entries), len(inventory.Issues)); err != nil {
		return err
	}
	for _, entry := range inventory.Entries {
		if _, err := fmt.Fprintf(output, "line %d  %s  %s/%d  options=%d\n", entry.Line, entry.Fingerprint, entry.Algorithm, entry.Bits, len(entry.Options)); err != nil {
			return err
		}
	}
	for _, issue := range inventory.Issues {
		if _, err := fmt.Fprintf(output, "warning %s at line %d: %s\n", issue.Code, issue.Line, issue.Message); err != nil {
			return err
		}
	}
	return nil
}
