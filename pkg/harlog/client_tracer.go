package harlog

import (
	"crypto/tls"
	"net/http/httptrace"
	"time"
)

// NewTimingTrace creates a timing trace together with an http client tracer that populates it.
// The third parameter is a function to call when the request is complete.
func NewTimingTrace() (*TimingTrace, *httptrace.ClientTrace) {
	timings := &TimingTrace{
		startAt: time.Now(),
	}
	tracer := &httptrace.ClientTrace{
		GetConn:              timings.GetConn,
		GotConn:              timings.GotConn,
		PutIdleConn:          nil,
		GotFirstResponseByte: timings.GotFirstResponseByte,
		Got100Continue:       nil,
		Got1xxResponse:       nil,
		DNSStart:             timings.DNSStart,
		DNSDone:              timings.DNSDone,
		ConnectStart:         nil,
		ConnectDone:          nil,
		TLSHandshakeStart:    timings.TLSHandshakeStart,
		TLSHandshakeDone:     timings.TLSHandshakeDone,
		WroteHeaderField:     nil,
		WroteHeaders:         nil,
		Wait100Continue:      nil,
		WroteRequest:         timings.WroteRequest,
	}

	return timings, tracer
}

type TimingTrace struct {
	startAt           time.Time
	connStart         time.Time
	connObtained      time.Time
	firstResponseByte time.Time
	dnsStart          time.Time
	dnsEnd            time.Time
	tlsHandshakeStart time.Time
	tlsHandshakeEnd   time.Time
	writeRequest      time.Time
	endAt             time.Time
}

func (ct *TimingTrace) GetConn(hostPort string) {
	ct.connStart = time.Now()
}

func (ct *TimingTrace) GotConn(info httptrace.GotConnInfo) {
	ct.connObtained = time.Now()
}

func (ct *TimingTrace) GotFirstResponseByte() {
	ct.firstResponseByte = time.Now()
}

func (ct *TimingTrace) DNSStart(info httptrace.DNSStartInfo) {
	ct.dnsStart = time.Now()
}

func (ct *TimingTrace) DNSDone(info httptrace.DNSDoneInfo) {
	ct.dnsEnd = time.Now()
}

func (ct *TimingTrace) TLSHandshakeStart() {
	ct.tlsHandshakeStart = time.Now()
}

func (ct *TimingTrace) TLSHandshakeDone(tls.ConnectionState, error) {
	ct.tlsHandshakeEnd = time.Now()
}

func (ct *TimingTrace) WroteRequest(info httptrace.WroteRequestInfo) {
	ct.writeRequest = time.Now()
}
