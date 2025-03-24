package main

import (
	"context"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

// code in this file is only used for the "homegrown" TCP and UDP stacks

// copyToDevice copies packets from a channel to a tun device
func copyToDevice(ctx context.Context, dst *water.Interface, src chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet := <-src:
			_, err := dst.Write(packet)
			if err != nil {
				errorf("error writing %d bytes to tun: %v, dropping and continuing...", len(packet), err)
			}

			if dumpPacketsToSubprocess {
				reply := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
				verbose(strings.Repeat("\n", 3))
				verbose(strings.Repeat("=", 80))
				verbose("To subprocess:")
				verbose(reply.Dump())
			} else {
				verbosef("transmitting %v raw bytes to subprocess", len(packet))
			}
		}
	}
}

// readFromDevice parses packets from a tun device and delivers them to the TCP and UDP stacks
func readFromDevice(ctx context.Context, tun *water.Interface, tcpstack *tcpStack, udpstack *udpStack) error {
	// start reading raw bytes from the tunnel device and sending them to the appropriate stack
	buf := make([]byte, 1500)
	for {
		// read a packet (TODO: implement non-blocking read on the file descriptor, check for context cancellation)
		n, err := tun.Read(buf)
		if err != nil {
			errorf("error reading a packet from tun: %v, ignoring", err)
			continue
		}

		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
		ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}

		tcp, isTCP := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		udp, isUDP := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !isTCP && !isUDP {
			continue
		}

		if dumpPacketsFromSubprocess {
			verbose(strings.Repeat("\n", 3))
			verbose(strings.Repeat("=", 80))
			verbose("From subprocess:")
			verbose(packet.Dump())
		}

		if isTCP {
			verbosef("received from subprocess: %v", summarizeTCP(ipv4, tcp, tcp.Payload))
			tcpstack.handlePacket(ipv4, tcp, tcp.Payload)
		}
		if isUDP {
			verbosef("received from subprocess: %v", summarizeUDP(ipv4, udp, udp.Payload))
			udpstack.handlePacket(ipv4, udp, udp.Payload)
		}
	}
}
