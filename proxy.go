package main

import (
	"io"
	"net"
)

// proxyConn proxies data received on one TCP connection to the world, and back the other way.
func proxyConn(network, addr string, subprocess net.Conn) {
	// the connections's "LocalAddr" is actually the address that the other side (the subprocess) was trying
	// to reach, so that's the address we dial in order to proxy
	world, err := net.Dial(network, addr)
	if err != nil {
		// TODO: report errors not related to destination being unreachable
		subprocess.Close()
		return
	}

	go proxyBytes(subprocess, world)
	go proxyBytes(world, subprocess)
}

// proxyBytes copies data between the world and the subprocess
func proxyBytes(w io.Writer, r io.Reader) {
	buf := make([]byte, 1<<20)
	for {
		n, err := r.Read(buf)
		if err == io.EOF {
			// how to indicate to outside world that we're done?
			return
		}
		if err != nil {
			// how to indicate to outside world that the read failed?
			errorf("error reading in proxyBytes: %v, abandoning", err)
			return
		}

		// send packet to channel, drop on failure
		_, err = w.Write(buf[:n])
		if err != nil {
			errorf("error writing in proxyBytes: %v, dropping %d bytes", err, n)
		}
	}
}
