package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"fmt"
	"html"
	stdfs "io/fs"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"text/template"
	"time"

	"github.com/crewjam/saml/samlsp"
)

//go:embed static/*
var staticFS embed.FS

//go:embed templates/flag.html
var flagHTML string
var tplFlag = template.Must(template.New("flag").Parse(flagHTML))

var flagValue = getenv("FLAG", "HeroCTF{CHANGE_ME}")

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func ensureKeyPair(dir, cn string) (tls.Certificate, *x509.Certificate, *rsa.PrivateKey) {
	_ = os.MkdirAll(dir, 0o755)
	certPath := filepath.Join(dir, "sp-cert.pem")
	keyPath := filepath.Join(dir, "sp-key.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		// generate self-signed
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		must(err)

		template := &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				CommonName: cn,
			},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
		must(err)

		certOut, err := os.Create(certPath)
		must(err)
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		certOut.Close()

		keyOut, err := os.Create(keyPath)
		must(err)
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
		keyOut.Close()
	}

	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	must(err)
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	must(err)
	priv := keyPair.PrivateKey.(*rsa.PrivateKey)
	return keyPair, leaf, priv
}

func isAdminFromAttrs(attrs samlsp.Attributes) bool {
	fmt.Println(attrs)
	return slices.Contains(attrs["eduPersonAffiliation"], "Administrators")
}

func main() {
	rootURL, _ := url.Parse("http://web.heroctf.fr:8080")

	idpMeta := getenv("IDP_METADATA_URL", "http://web.heroctf.fr:8081/metadata")
	idpMDURL, _ := url.Parse(idpMeta)

	_, cert, priv := ensureKeyPair("./data", "saml-sp-local")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	idpMetadata, err := samlsp.FetchMetadata(ctx, http.DefaultClient, *idpMDURL)
	must(err)

	samlSP, err := samlsp.New(samlsp.Options{
		URL:         *rootURL,    // base de l’appli
		Key:         priv,        // clé privée du SP
		Certificate: cert,        // cert du SP
		IDPMetadata: idpMetadata, // metadata de l’IdP
	})

	samlSP.ServiceProvider.AllowIDPInitiated = true

	must(err)

	http.Handle("/saml/", samlSP)
	http.Handle("/flag", samlSP.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := samlsp.SessionFromContext(r.Context())
		var attrs samlsp.Attributes
		if sa, ok := sess.(samlsp.SessionWithAttributes); ok {
			attrs = sa.GetAttributes()
		} else {
			attrs = samlsp.Attributes{}
		}

		nameID := samlsp.AttributeFromContext(r.Context(), "uid")
		if nameID == "" {
			nameID = samlsp.AttributeFromContext(r.Context(), "email")
		}
		if nameID == "" {
			nameID = "utilisateur"
		}

		data := struct {
			Name    string
			NameID  string
			IsAdmin bool
			Flag    string
			Attrs   samlsp.Attributes
		}{
			Name:    html.EscapeString(nameID),
			NameID:  html.EscapeString(nameID),
			IsAdmin: isAdminFromAttrs(attrs),
			Flag:    flagValue,
			Attrs:   attrs,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tplFlag.Execute(w, data); err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
		}
	})))

	sub, err := stdfs.Sub(staticFS, "static")
	must(err)
	staticServer := http.FileServer(http.FS(sub))
	http.Handle("/", staticServer)

	http.HandleFunc("/local-login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/?error=badpass", http.StatusSeeOther)
	})

	log.Println("SP listening on http://web.heroctf.fr:8080")
	must(http.ListenAndServe(":8080", nil))
}
