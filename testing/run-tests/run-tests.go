package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/gobwas/glob"
)

type Case struct {
	Target string // name of the makefile target
	Output string // output expected from this target
	Exit   int    // exit code expected from this target
}

func Main() error {
	var args struct {
		Path    string `default:"Makefile"`
		Pattern string `arg:"positional" default:"test-*"`
		Verbose bool   `arg:"-v,--verbose"`
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
		} else if strings.HasPrefix(line, "# ") && inOutput && cur != nil {
			if cur.Output != "" {
				cur.Output += "\n"
			}
			cur.Output += line[2:]
		} else if !strings.HasPrefix(line, "# ") {
			inOutput = false
		}
	}

	// select the cases matching the glob pattern
	var selected []*Case
	for _, c := range cases {
		if pattern.Match(c.Target) {
			selected = append(selected, c)
		}
	}

	// run the cases
	success := true
	for _, c := range selected {
		if args.Verbose {
			log.Println(c.Target + " ->")
			log.Printf("%q", c.Output)
		}

		// run make <target>
		cmd := exec.Command("make", "-s", "-f", args.Path, c.Target)
		b, err := cmd.CombinedOutput()
		out := strings.TrimSpace(string(b))
		if err != nil {
			success = false
			if err, isExit := err.(*exec.ExitError); isExit {
				log.Printf("%s exited with code %d:", c.Target, err.ExitCode())
				log.Println(out)
			} else {
				return fmt.Errorf("error running %v: %w", strings.Join(cmd.Args, " "))
			}
		}

		if out != c.Output {
			success = false
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

	if success {
		log.Printf("%d tests passed", len(selected))
	}

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
