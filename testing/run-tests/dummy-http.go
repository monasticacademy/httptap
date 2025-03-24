package main

import (
	"log"
	"net/http"
)

func handleDummyText(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello from dummy-http"))
}

func init() {
	http.HandleFunc("/text", handleDummyText)
}

// run an HTTP server with endpoints that used in the test cases
func dummyHTTP(addr string) {
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatal(err)
	}
}

// run an HTTP server with endpoints that used in the test cases
func dummyHTTPS(addr, certFile, keyFile string) {
	err := http.ListenAndServeTLS(addr, certFile, keyFile, nil)
	if err != nil {
		log.Fatal(err)
	}
}
