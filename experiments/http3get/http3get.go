package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"

	"github.com/alexflint/go-arg"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	var args struct {
		URL string `arg:"positional,required"`
	}
	arg.MustParse(&args)

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{},  // set a TLS client config, if desired
		QUICConfig:      &quic.Config{}, // QUIC connection options
	}
	defer tr.Close()
	client := &http.Client{
		Transport: tr,
	}

	r, err := client.Get(args.URL)
	if err != nil {
		log.Fatal("error performing GET request: ", err)
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatal("error reading response body: ", err)
	}

	log.Printf("read %d bytes", len(b))
}
