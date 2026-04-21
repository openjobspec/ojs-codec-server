// Command ojs-attest is the M1/P1 prototype CLI for the ext_attest
// envelope key (RFC-0010-ext-attest.md). Three subcommands:
//
//	ojs-attest keygen  -seed seed.bin -pub pub.bin
//	ojs-attest sign    -seed seed.bin -key-id <id> -input args.json [-output out.json] [-document doc.bin]
//	                 [-attest-type signature-only]
//	ojs-attest verify  -pub pub.bin -evidence evidence.json
//
// The wire shape of the emitted "evidence" file is exactly the
// ext_attest envelope-key payload defined by RFC-0010, so the same JSON
// can be embedded under "ext_attest" in any OJS envelope unchanged.
//
// This is the auditor-facing companion to ctn-submit: a partner uses
// ojs-attest sign to attach attestation to a job result, and any
// downstream verifier uses ojs-attest verify (or any compatible
// implementation) to confirm provenance.
package main

import (
	"fmt"
	"os"
)

const version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("ojs-attest", version)
	case "keygen":
		if err := keygen(os.Args[2:]); err != nil {
			fail(err)
		}
	case "sign":
		if err := sign(os.Args[2:]); err != nil {
			fail(err)
		}
	case "verify":
		if err := verify(os.Args[2:]); err != nil {
			fail(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ojs-attest <keygen|sign|verify|version> [flags]")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ojs-attest:", err)
	os.Exit(1)
}
