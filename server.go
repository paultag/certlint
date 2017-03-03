package main

import (
	"encoding/pem"
	"html/template"
	"log"
	"net/http"

	"crypto/tls"
	"crypto/x509"
)

func handleError(w http.ResponseWriter, req *http.Request, err error) error {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(500)
	w.Write([]byte(err.Error()))
	return nil

}

type Certificates struct {
	Certificates []*x509.Certificate
}

func LintServer(w http.ResponseWriter, req *http.Request) {
	pages, err := template.New("").Funcs(template.FuncMap{
		"toPEM": func(type_ string, data interface{}) (string, error) {
			der, err := x509.MarshalPKIXPublicKey(data)
			if err != nil {
				return "", err
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{
				Type:  type_,
				Bytes: der,
			})
			if err != nil {
				return "", err
			}
			return string(pemBytes), nil
		},
	}).ParseFiles("templates/index.html")
	if err != nil {
		handleError(w, req, err)
		return
	}

	if err = pages.ExecuteTemplate(w, "index.html", Certificates{
		Certificates: req.TLS.PeerCertificates,
	}); err != nil {
		log.Printf("%s\n", err)
		return
	}
	return
}

func main() {
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.HandleFunc("/", LintServer)

	tlsConfig := &tls.Config{ClientAuth: tls.RequestClientCert}
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
