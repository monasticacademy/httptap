package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/miekg/dns"
)

// handle resolves IPv4 hosts according to net.DefaultResolver
func handle(requestMsg *dns.Msg) ([]dns.RR, error) {
	if len(requestMsg.Question) == 0 {
		return nil, nil // this means no answer, no error, which is fine
	}

	question := requestMsg.Question[0]
	log.Printf("got dns request for %v", question.Name)

	ctx := context.Background()

	// handle the request ourselves
	switch question.Qtype {
	case dns.TypeA:
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", question.Name)
		if err != nil {
			return nil, fmt.Errorf("the default resolver said: %w", err)
		}

		var rrs []dns.RR
		for _, ip := range ips {
			rrline := fmt.Sprintf("%s A %s", question.Name, ip)
			rr, err := dns.NewRR(rrline)
			if err != nil {
				return nil, fmt.Errorf("error constructing rr: %w", err)
			}
			rrs = append(rrs, rr)
		}
		return rrs, nil
	}

	log.Println("proxying the request...")

	dnsClientConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("could not parse /etc/resolv.conf: %w", err)
	}

	// proxy the request to another server
	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{question}

	dnsClient := new(dns.Client)
	dnsClient.Net = "udp"
	var (
		response *dns.Msg
		errs     []error
	)
	for _, dnsServer := range dnsClientConfig.Servers {
		response, _, err = dnsClient.Exchange(queryMsg, dnsServer)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		break
	}

	if len(errs) > 0 {
		var errStr []string
		for _, err := range errs {
			errStr = append(errStr, err.Error())
		}
		return nil, errors.New(strings.Join(errStr, ", "))
	}

	log.Printf("got answer from upstream dns server with %d answers", len(response.Answer))

	if len(response.Answer) > 0 {
		return response.Answer, nil
	}
	return nil, fmt.Errorf("not found")
}

func Main() error {
	var args struct {
		Port string `arg:"positional"`
	}
	arg.MustParse(&args)

	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		switch req.Opcode {
		case dns.OpcodeQuery:
			rrs, err := handle(req)
			if err != nil {
				log.Printf("dns failed for %s with error: %v, continuing...", req, err.Error())
				// do not abort here, continue on
			}

			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = rrs
			w.WriteMsg(resp)
		}
	})

	server := &dns.Server{Addr: args.Port, Net: "udp"}
	server.ListenAndServe()
	log.Printf("listening on %v...", server.Addr)
	return server.ListenAndServe()
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}
