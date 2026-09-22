// Command mtls-server is a minimal TLS server that requires a client
// certificate, used by wrest's CI to prove that a tls::Identity taken from
// the Windows certificate store is actually presented during a handshake.
//
// /client-cert answers with the hex SHA-1 thumbprint of the certificate
// presented, so the test asserts which certificate arrived rather than
// that some handshake succeeded.  Chains are deliberately not verified
// (RequireAnyClientCert): the certificate is self-signed by Windows, so
// path building would test x509 rather than wrest.
//
// Stdlib only, so CI needs no module downloads beyond the toolchain.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	flag.Parse()

	cert, err := selfSignedServerCert()
	if err != nil {
		log.Fatalf("generating server certificate: %v", err)
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listening on %s: %v", *addr, err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(clientCertHandler),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAnyClientCert,
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}

	// The readiness line the CI action waits for.
	fmt.Printf("mtls-server ready on %s\n", listener.Addr())
	log.Fatal(server.ServeTLS(listener, "", ""))
}

// clientCertHandler answers with the thumbprint of the certificate the
// client presented.
func clientCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		// Unreachable with RequireAnyClientCert, but a 403 is a far clearer
		// CI failure than a panic.
		http.Error(w, "no client certificate presented", http.StatusForbidden)
		return
	}
	sum := sha1.Sum(r.TLS.PeerCertificates[0].Raw)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, hex.EncodeToString(sum[:]))
}

// selfSignedServerCert builds a throwaway certificate for 127.0.0.1.  The
// tests disable server certificate validation -- they exercise client
// authentication, not chain building -- so this only has to be well-formed.
func selfSignedServerCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wrest-test-server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}
