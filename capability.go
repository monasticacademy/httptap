package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// parse /proc/self/status and extract the CapEff line that looks like:
//
// CapEff:	000001ffffffffff
func capabilities() (uint64, error) {
	buf, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}

	s := string(buf)
	pos := strings.Index(s, "CapEff:")
	if pos == -1 {
		return 0, fmt.Errorf("no CapEff line found in /proc/self/status")
	}

	s = s[pos+len("CapEff:"):]
	sz := strings.Index(s, "\n")
	if sz == -1 {
		return 0, fmt.Errorf("no newline found after CapEff in /proc/self/status")
	}

	cap, err := strconv.ParseUint(strings.TrimSpace(s[:sz]), 16, 64)
	if err != nil {
		return 0, err
	}

	verbosef("we have capabilities: %x", cap)
	return cap, nil
}
