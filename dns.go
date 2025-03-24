package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/miekg/dns"
)

// dnsCall is a summary of a dns request/response exposed to the application level observers
type dnsCall struct {
	queries []dnsQuery
}

// a dnsQuery is a query/response pair
type dnsQuery interface {
	Type() string
	Query() string
	Answers() []string
}

// dnsPairA is an A or AAAA query together with responses
type dnsPairA struct {
	typ     uint16
	query   string
	answers []net.IP
}

func (p dnsPairA) Type() string {
	return dnsTypeCode(p.typ)
}

func (p dnsPairA) Query() string {
	return p.query
}

func (p dnsPairA) Answers() []string {
	var answers []string
	for _, a := range p.answers {
		answers = append(answers, a.String())
	}
	return answers
}

// dnsWatcher receives information about each intercepted DNS query, and the response provided
type dnsWatcher func(*dnsCall)

// the listeners waiting for HTTPCalls
var dnsWatchers []dnsWatcher

// the mutex that protects the above slice
var dnsMu sync.Mutex

// add a watcher that will called for each DNS request/response
func watchDNS(w dnsWatcher) {
	dnsMu.Lock()
	defer dnsMu.Unlock()

	dnsWatchers = append(dnsWatchers, w)
}

// call each DNS watcher
func notifyDNSWatchers(call *dnsCall) {
	dnsMu.Lock()
	defer dnsMu.Unlock()

	verbosef("notifying DNS watchers (%d query/response pairs)", len(call.queries))

	for _, w := range dnsWatchers {
		w(call)
	}
}

// handle a DNS query payload here is the application-level UDP payload
func handleDNS(ctx context.Context, w io.Writer, payload []byte) {
	var req dns.Msg
	err := req.Unpack(payload)
	if err != nil {
		errorf("error unpacking dns packet: %v, ignoring", err)
		return
	}

	if req.Opcode != dns.OpcodeQuery {
		errorf("ignoring a dns query with non-query opcode (%v)", req.Opcode)
		return
	}

	// resolve the query
	rrs, err := handleDNSQuery(ctx, &req)
	if err != nil {
		verbosef("DNS query returned: %v, sending a response with empty answer", err)
		// do not abort here, continue on and send a reply with no answer
	}

	resp := new(dns.Msg)
	resp.SetReply(&req)
	resp.Answer = rrs

	// serialize the response
	buf, err := resp.Pack()
	if err != nil {
		errorf("error serializing dns response: %v, abandoning...", err)
		return
	}

	// always send the entire buffer in a single Write() since UDP writes one packet per call to Write()
	verbosef("responding to DNS request with %d bytes...", len(buf))
	_, err = w.Write(buf)
	if err != nil {
		errorf("error writing dns response: %v, abandoning...", err)
		return
	}
}

func dnsTypeCode(t uint16) string {
	switch t {
	case dns.TypeNone:
		return "<None>"
	case dns.TypeA:
		return "A"
	case dns.TypeNS:
		return "NS"
	case dns.TypeMD:
		return "MD"
	case dns.TypeMF:
		return "MF"
	case dns.TypeCNAME:
		return "CNAME"
	case dns.TypeSOA:
		return "SOA"
	case dns.TypeMB:
		return "MB"
	case dns.TypeMG:
		return "MG"
	case dns.TypeMR:
		return "MR"
	case dns.TypeNULL:
		return "NULL"
	case dns.TypePTR:
		return "PTR"
	case dns.TypeHINFO:
		return "HINFO"
	case dns.TypeMINFO:
		return "MINFO"
	case dns.TypeMX:
		return "MX"
	case dns.TypeTXT:
		return "TXT"
	case dns.TypeRP:
		return "RP"
	case dns.TypeAFSDB:
		return "AFSDB"
	case dns.TypeX25:
		return "X25"
	case dns.TypeISDN:
		return "ISDN"
	case dns.TypeRT:
		return "RT"
	case dns.TypeNSAPPTR:
		return "NSAPPTR"
	case dns.TypeSIG:
		return "SIG"
	case dns.TypeKEY:
		return "KEY"
	case dns.TypePX:
		return "PX"
	case dns.TypeGPOS:
		return "GPOS"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeLOC:
		return "LOC"
	case dns.TypeNXT:
		return "NXT"
	case dns.TypeEID:
		return "EID"
	case dns.TypeNIMLOC:
		return "NIMLOC"
	case dns.TypeSRV:
		return "SRV"
	case dns.TypeATMA:
		return "ATMA"
	case dns.TypeNAPTR:
		return "NAPTR"
	case dns.TypeKX:
		return "KX"
	case dns.TypeCERT:
		return "CERT"
	case dns.TypeDNAME:
		return "DNAME"
	case dns.TypeOPT:
		return "OPT"
	case dns.TypeAPL:
		return "APL"
	case dns.TypeDS:
		return "DS"
	case dns.TypeSSHFP:
		return "SSHFP"
	case dns.TypeIPSECKEY:
		return "IPSECKEY"
	case dns.TypeRRSIG:
		return "RRSIG"
	case dns.TypeNSEC:
		return "NSEC"
	case dns.TypeDNSKEY:
		return "DNSKEY"
	case dns.TypeDHCID:
		return "DHCID"
	case dns.TypeNSEC3:
		return "NSEC3"
	case dns.TypeNSEC3PARAM:
		return "NSEC3PARAM"
	case dns.TypeTLSA:
		return "TLSA"
	case dns.TypeSMIMEA:
		return "SMIMEA"
	case dns.TypeHIP:
		return "HIP"
	case dns.TypeNINFO:
		return "NINFO"
	case dns.TypeRKEY:
		return "RKEY"
	case dns.TypeTALINK:
		return "TALINK"
	case dns.TypeCDS:
		return "CDS"
	case dns.TypeCDNSKEY:
		return "CDNSKEY"
	case dns.TypeOPENPGPKEY:
		return "OPENPGPKEY"
	case dns.TypeCSYNC:
		return "CSYNC"
	case dns.TypeZONEMD:
		return "ZONEMD"
	case dns.TypeSVCB:
		return "SVCB"
	case dns.TypeHTTPS:
		return "HTTPS"
	case dns.TypeSPF:
		return "SPF"
	case dns.TypeUINFO:
		return "UINFO"
	case dns.TypeUID:
		return "UID"
	case dns.TypeGID:
		return "GID"
	case dns.TypeUNSPEC:
		return "UNSPEC"
	case dns.TypeNID:
		return "NID"
	case dns.TypeL32:
		return "L32"
	case dns.TypeL64:
		return "L64"
	case dns.TypeLP:
		return "LP"
	case dns.TypeEUI48:
		return "EUI48"
	case dns.TypeEUI64:
		return "EUI64"
	case dns.TypeNXNAME:
		return "NXNAME"
	case dns.TypeURI:
		return "URI"
	case dns.TypeCAA:
		return "CAA"
	case dns.TypeAVC:
		return "AVC"
	case dns.TypeAMTRELAY:
		return "AMTRELAY"
	case dns.TypeTKEY:
		return "TKEY"
	case dns.TypeTSIG:
		return "TSIG"
	case dns.TypeIXFR:
		return "IXFR"
	case dns.TypeAXFR:
		return "AXFR"
	case dns.TypeMAILB:
		return "MAILB"
	case dns.TypeMAILA:
		return "MAILA"
	case dns.TypeANY:
		return "ANY"
	case dns.TypeTA:
		return "TA"
	case dns.TypeDLV:
		return "DLV"
	case dns.TypeReserved:
		return "Reserved"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// TCP connections to this hostname will be routed to localhost on the host network
const specialHostName = "host.httptap.local"

// TCP connections to this IP address will be routed to localhost on the host network
const specialHostIP = "169.254.77.65"

// this map contains hardcoded DNS names
var specialAddresses = map[string]net.IP{
	specialHostName + ".": {169, 254, 77, 65},
}

// handleDNSQuery answers DNS queries according to:
//
//	net.DefaultResolver if the DNS request is A or AAAA
//	cloudflare DNS for other DNS requests
//
// It always returns the special IP 169.254.77.65 for the special name host.httptap.local.
// Traffic sent to this address is routed to the loopback interface on the host (different
// from the loopback device seen by the subprocess)
func handleDNSQuery(ctx context.Context, req *dns.Msg) ([]dns.RR, error) {
	const upstreamDNS = "1.1.1.1:53" // TODO: get from resolv.conf and nsswitch.conf

	if len(req.Question) == 0 {
		return nil, nil // this means no answer, no error, which is fine
	}

	question := req.Question[0]
	questionType := dnsTypeCode(question.Qtype)
	verbosef("got dns request for %v (%v)", question.Name, questionType)

	// the DNS call will be sent to watchers later
	var call dnsCall

	// handle the request ourselves
	switch question.Qtype {
	case dns.TypeA:
		var ips []net.IP
		if ip, ok := specialAddresses[question.Name]; ok {
			ips = append(ips, ip)
		} else {
			var err error
			ips, err = net.DefaultResolver.LookupIP(ctx, "ip4", question.Name)
			if err != nil {
				return nil, fmt.Errorf("for an A record the default resolver said: %w", err)
			}
		}

		call.queries = append(call.queries, dnsPairA{
			typ:     dns.TypeA,
			query:   question.Name,
			answers: ips,
		})

		verbosef("resolved %v to %v with default resolver", question.Name, ips)

		var rrs []dns.RR
		for _, ip := range ips {
			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", question.Name, ip))
			if err != nil {
				return nil, fmt.Errorf("error constructing rr: %w", err)
			}
			rrs = append(rrs, rr)
		}

		// notify DNS watchers of the request/response pairs
		notifyDNSWatchers(&call)

		return rrs, nil

	case dns.TypeAAAA:
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip6", question.Name)
		if err != nil {
			return nil, fmt.Errorf("for an AAAA record the default resolver said (AAAA record): %w", err)
		}

		call.queries = append(call.queries, dnsPairA{
			typ:     dns.TypeAAAA,
			query:   question.Name,
			answers: ips,
		})

		verbosef("resolved %v to %v with default resolver", question.Name, ips)

		var rrs []dns.RR
		for _, ip := range ips {
			rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", question.Name, ip))
			if err != nil {
				return nil, fmt.Errorf("error constructing rr: %w", err)
			}
			rrs = append(rrs, rr)
		}

		// notify DNS watchers of the request/response pairs
		notifyDNSWatchers(&call)

		return rrs, nil
	}

	verbosef("proxying %s request to upstream DNS server...", questionType)

	// proxy the request to another server
	request := new(dns.Msg)
	req.CopyTo(request)
	request.Question = []dns.Question{question}

	dnsClient := new(dns.Client)
	dnsClient.Net = "udp"
	response, _, err := dnsClient.Exchange(request, upstreamDNS)
	if err != nil {
		return nil, fmt.Errorf("error in DNS message exchange: %w", err)
	}

	verbosef("got answer from upstream dns server with %d answers", len(response.Answer))

	// note that we might have 0 answers here: this means there were no records for the query, which is not an error
	return response.Answer, nil
}
