package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/gobwas/glob"
	"github.com/joemiller/certin"
	"github.com/monasticacademy/httptap/pkg/certfile"
)

type Case struct {
	Target string // name of the makefile target
	Output string // output expected from this target
}

func Main() error {
	var args struct {
		Path    string `default:"Makefile"`
		Pattern string `arg:"positional,env:PATTERN" default:"test-*"`
		TLSCert string
		TLSKey  string
		Exclude []string
		Verbose bool `arg:"-v,--verbose"`
	}
	arg.MustParse(&args)

	buf, err := os.ReadFile(args.Path)
	if err != nil {
		return err
	}

	pattern, err := glob.Compile(args.Pattern)
	if err != nil {
		return fmt.Errorf("bad glob %q: %w", args.Pattern, err)
	}

	var exclude []glob.Glob
	for _, s := range args.Exclude {
		pat, err := glob.Compile(s)
		if err != nil {
			return fmt.Errorf("bad glob %q: %w", args.Pattern, err)
		}
		exclude = append(exclude, pat)
	}

	var cases []*Case

	lines := strings.Split(string(buf), "\n")
	var inOutput bool
	var cur *Case
	for _, line := range lines {
		if pos := strings.Index(line, ":"); pos >= 0 && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "#") {
			cur = &Case{Target: line[:pos]}
			cases = append(cases, cur)
		}

		pos := strings.Index(line, "# Output:")

		if pos == 0 {
			inOutput = true
		} else if pos > 0 && cur != nil {
			cur.Output = strings.TrimSpace(line[pos+len("# Output:"):])
		} else if strings.HasPrefix(line, "#") && inOutput && cur != nil {
			if cur.Output != "" {
				cur.Output += "\n"
			}
			cur.Output += strings.TrimSpace(strings.TrimPrefix(line, "#"))
		} else if !strings.HasPrefix(line, "#") {
			inOutput = false
		}
	}

	// select the cases matching the glob pattern
	var selected []*Case
outer:
	for _, c := range cases {
		if !pattern.Match(c.Target) {
			continue
		}
		for _, g := range exclude {
			if g.Match(c.Target) {
				continue outer
			}
		}
		selected = append(selected, c)
	}

	// create TLS certificate authority
	ca, err := certin.NewCert(nil, certin.Request{CN: "root CA", IsCA: true})
	if err != nil {
		return fmt.Errorf("error creating root CA: %w", err)
	}

	// create a temporary directory
	tempdir, err := os.MkdirTemp("", "")
	if err != nil {
		return fmt.Errorf("error creating temporary directory: %w", err)
	}
	defer os.RemoveAll(tempdir)

	// marshal certificate authority to PEM format
	caPEM, err := certfile.MarshalPEM(ca.Certificate)
	if err != nil {
		return fmt.Errorf("error marshaling certificate authority to PEM format: %w", err)
	}

	// write certificate authority to PEM file
	caPath := filepath.Join(tempdir, "ca.crt")
	err = os.WriteFile(caPath, caPEM, 0666)
	if err != nil {
		return fmt.Errorf("error writing certificate authority to temporary PEM file: %w", err)
	}

	// start the http server that many of the test cases use
	go dummyHTTP(":8080")
	go dummyHTTPS(":8443", args.TLSCert, args.TLSKey)

	// run the cases
	var failures int
	for _, c := range selected {
		log.Println(c.Target)

		// run make <target>
		cmd := exec.Command("make", "-s", "-f", args.Path, c.Target)
		b, err := cmd.CombinedOutput()
		out := strings.TrimSpace(string(b))
		if err != nil {
			failures++
			if err, isExit := err.(*exec.ExitError); isExit {
				log.Printf("%v exited with code %v and the following output", c.Target, err.ExitCode())
				log.Println(out)
				continue
			} else {
				return fmt.Errorf("error running %v: %w", strings.Join(cmd.Args, " "), err)
			}
		}

		if out != c.Output {
			failures++
			if strings.Contains(out, "\n") || strings.Contains(c.Output, "\n") {
				log.Printf("%s output incorrect:", c.Target)
				log.Println(out)
				log.Println("Expected:")
				log.Println(c.Output)
			} else {
				log.Printf("%s output was %q, expected %q", c.Target, out, c.Output)
			}
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d of %d tests failed", failures, len(selected))
	}

	log.Printf("%d tests passed", len(selected))
	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}
