// Command mtls-server is a minimal TLS server used by wrest's CI, with two
// listeners sharing one self-signed certificate:
//
//   - -addr (mutual TLS): requires a client certificate and answers
//     /client-cert with the hex SHA-1 thumbprint of the one presented, so
//     the test asserts which certificate arrived rather than that some
//     handshake succeeded. Chains are deliberately not verified
//     (RequireAnyClientCert): the certificate is self-signed by Windows, so
//     path building would test x509 rather than wrest.
//
//   - -redirect-addr (plain TLS): no client certificate, serving an
//     httpbin-compatible /redirect-to?url=...&status_code=... so the
//     https->http downgrade test has a local https origin instead of
//     httpbin.org.
//
// -cert-out writes the certificate so CI can trust it, which the redirect
// test needs: it exercises the *default* client, which validates the chain.
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
	"os"
	"strconv"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "mutual-TLS listen address")
	redirectAddr := flag.String("redirect-addr", "127.0.0.1:8444", "plain-TLS listen address")
	certOut := flag.String("cert-out", "", "write the server certificate (DER) here")
	flag.Parse()

	cert, der, err := selfSignedServerCert()
	if err != nil {
		log.Fatalf("generating server certificate: %v", err)
	}

	if *certOut != "" {
		if err := os.WriteFile(*certOut, der, 0o644); err != nil {
			log.Fatalf("writing %s: %v", *certOut, err)
		}
	}

	mtlsListener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listening on %s: %v", *addr, err)
	}
	redirectListener, err := net.Listen("tcp", *redirectAddr)
	if err != nil {
		log.Fatalf("listening on %s: %v", *redirectAddr, err)
	}

	mtls := &http.Server{
		Handler:           http.HandlerFunc(clientCertHandler),
		TLSConfig:         baseTLSConfig(cert, tls.RequireAnyClientCert),
		ReadHeaderTimeout: 10 * time.Second,
	}
	redirect := &http.Server{
		Handler:           http.HandlerFunc(redirectHandler),
		TLSConfig:         baseTLSConfig(cert, tls.NoClientCert),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() { log.Fatal(redirect.ServeTLS(redirectListener, "", "")) }()

	// The readiness line the CI action waits for; printed only once both
	// listeners are bound.
	fmt.Printf("mtls-server ready on %s and %s\n", mtlsListener.Addr(), redirectListener.Addr())
	log.Fatal(mtls.ServeTLS(mtlsListener, "", ""))
}

func baseTLSConfig(cert tls.Certificate, clientAuth tls.ClientAuthType) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS12,
	}
}

// clientCertHandler answers with the thumbprint of the presented certificate.
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

// redirectHandler mimics go-httpbin's /redirect-to, which cannot serve this
// case itself because CI runs it over plain http and the downgrade policy
// only fires on an https origin.
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	target := query.Get("url")
	if target == "" {
		http.Error(w, "missing url parameter", http.StatusBadRequest)
		return
	}

	status := http.StatusFound
	if raw := query.Get("status_code"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 300 || parsed > 399 {
			http.Error(w, "status_code must be 3xx", http.StatusBadRequest)
			return
		}
		status = parsed
	}

	w.Header().Set("Location", target)
	w.WriteHeader(status)
}

// selfSignedServerCert builds a throwaway certificate for 127.0.0.1, and
// returns its DER so CI can add it to the trust store.
func selfSignedServerCert() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wrest-mtls-test-server"},
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
		return tls.Certificate{}, nil, err
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, der, nil
}
