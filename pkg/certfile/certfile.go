package certfile

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// MarshalPEM encodes an x509 certficate to bytes in PEM format
func MarshalPEM(certificate *x509.Certificate) ([]byte, error) {
	var b bytes.Buffer
	err := pem.Encode(&b, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// WritePEM writes an x509 certificate to a PEM file
func WritePEM(path string, certificate *x509.Certificate) (err error) {
	var f *os.File
	f, err = os.Create(path)
	if err != nil {
		return err
	}

	defer func() {
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
	}()

	return pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})
}

// WritePKCS12 writes an x509 certificate to PKCS12 file
func WritePKCS12(path string, certificate *x509.Certificate) error {
	truststore, err := pkcs12.Passwordless.EncodeTrustStore([]*x509.Certificate{certificate}, "")
	if err != nil {
		return fmt.Errorf("error encoding certificate authority in pkcs12 format: %w", err)
	}

	return os.WriteFile(path, truststore, os.ModePerm)
}
