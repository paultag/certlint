package main

import (
	"io"
	"net/http"

	"crypto/tls"
)

func LintServer(w http.ResponseWriter, req *http.Request) {
	for _, cert := range req.TLS.PeerCertificates {
		io.WriteString(w, cert.Subject.CommonName)
	}
}

func main() {
	http.HandleFunc("/", LintServer)

	tlsConfig := &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	tlsConfig.BuildNameToCertificate()

	server := &http.Server{
		Addr:      ":8080",
		TLSConfig: tlsConfig,
	}

	server.ListenAndServeTLS(
		"/home/paultag/.keys/nyx.pault.ag.crt",
		"/home/paultag/.keys/nyx.pault.ag.key",
	)
}
