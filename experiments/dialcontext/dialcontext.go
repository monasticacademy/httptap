// dialcontext is a program to investigate whether an http request's context is passed through to
// the DialContext function on a http.Transport

package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/alexflint/go-arg"
)

type contextKey string

var fooKey contextKey = "dialcontext.foo"

func Main() error {
	ctx := context.Background()

	var args struct{}
	arg.MustParse(&args)

	// first construct an http transport
	transport := http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			log.Printf("at dialcontext, got value %q", ctx.Value(fooKey))
			return net.Dial(network, address)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          5,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}

	// now make a context containing a foo key
	ctx = context.WithValue(ctx, fooKey, "hello dialcontext!")

	// now make an ordinary http request
	req, err := http.NewRequest("GET", "https://www.monasticacademy.org", nil)
	if err != nil {
		return err
	}

	// add the context to the request
	req = req.WithContext(ctx)

	// send the request
	_, err = transport.RoundTrip(req)
	if err != nil {
		return err
	}

	log.Println("done")
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
