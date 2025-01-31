package main

// the type for context keys created by this package
type contextKey string

// a value for this context key is set on all HTTP requests intercepted by httptap, and is used
// in the DialContext function associated with http transports to dial the same hostname that
// the subprocess was dialing, regardless of what hostname is in HTTP request.
var dialToContextKey contextKey = "httptap.dialTo"
