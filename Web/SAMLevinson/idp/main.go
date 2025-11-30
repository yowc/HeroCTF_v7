package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlidp"
	"github.com/crewjam/saml/samlsp"
	"golang.org/x/crypto/bcrypt"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func createUsers(idpServer *samlidp.Server) error {
	userHashedPassword, _ := bcrypt.GenerateFromPassword([]byte("oyJPNYd3HgeBkaE%!rP#dZvqf2z*4$^qcCW4V6WM"), bcrypt.DefaultCost)
	if err := idpServer.Store.Put("/users/user", samlidp.User{
		Name: "user", HashedPassword: userHashedPassword, Groups: []string{"Users"},
	}); err != nil {
		return err
	}

	adminHashedPassword, _ := bcrypt.GenerateFromPassword([]byte("KK62f#fHvY!e4zYQk@mkYbXs9MPFiX#*C36vfzB9"), bcrypt.DefaultCost)
	if err := idpServer.Store.Put("/users/admin", samlidp.User{
		Name: "admin", HashedPassword: adminHashedPassword, Groups: []string{"Administrators", "Users"},
	}); err != nil {
		return err
	}
	return nil
}

func ensureKeyPair(dir, cn string) (tls.Certificate, *x509.Certificate, *rsa.PrivateKey) {
	_ = os.MkdirAll(dir, 0o755)
	certPath := filepath.Join(dir, "idp-cert.pem")
	keyPath := filepath.Join(dir, "idp-key.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
		must(err)

		template := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: cn},
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
		_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		_ = certOut.Close()

		keyOut, err := os.Create(keyPath)
		must(err)
		_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
		_ = keyOut.Close()
	}

	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	must(err)
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	must(err)
	priv := keyPair.PrivateKey.(*rsa.PrivateKey)
	return keyPair, leaf, priv
}

// --- debug storage ---
var lastPre, lastPost []byte
var lastMu sync.Mutex

func main() {
	idpURL, _ := url.Parse("http://web.heroctf.fr:8081")
	_, cert, priv := ensureKeyPair("./data", "saml-idp-local")

	s, err := samlidp.New(samlidp.Options{
		URL: *idpURL, Key: priv, Certificate: cert, Store: &samlidp.MemoryStore{},
	})
	must(err)
	s.InitializeHTTP()

	ssoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, r)
		body := rr.Body.Bytes()

		nameIdx := bytes.Index(body, []byte(`name="SAMLResponse"`))
		if nameIdx < 0 {
			log.Println("IdP/sso: no SAMLResponse field found")
			copyThrough(w, rr, body)
			return
		}
		valIdx := bytes.Index(body[nameIdx:], []byte(`value="`))
		if valIdx < 0 {
			log.Println("IdP/sso: no value for SAMLResponse")
			copyThrough(w, rr, body)
			return
		}
		valStart := nameIdx + valIdx + len(`value="`)
		valEnd := bytes.IndexByte(body[valStart:], '"')
		if valEnd < 0 {
			log.Println("IdP/sso: unterminated value for SAMLResponse")
			copyThrough(w, rr, body)
			return
		}

		b64 := body[valStart : valStart+valEnd]
		raw, err := base64.StdEncoding.DecodeString(string(b64))
		if err != nil {
			log.Printf("IdP/sso: base64 decode error: %v", err)
			copyThrough(w, rr, body)
			return
		}

		//
		iAsrt := bytes.Index(raw, []byte("<saml:Assertion"))
		head := raw
		tail := []byte{}
		if iAsrt >= 0 {
			head = raw[:iAsrt]
			tail = raw[iAsrt:]
		}

		reRespSig := regexp.MustCompile(`(?s)<ds:Signature\b.*?</ds:Signature>`)
		head2 := reRespSig.ReplaceAll(head, []byte{})
		if !bytes.Equal(head, head2) {
			log.Println("IdP/sso: stripped Response-level <ds:Signature>")
		}
		head = head2

		reRespOpen := regexp.MustCompile(`(?s)<samlp:Response[^>]*>`)
		head = reRespOpen.ReplaceAllFunc(head, func(open []byte) []byte {
			reIR := regexp.MustCompile(`\sInResponseTo="[^"]+"`)
			out := reIR.ReplaceAll(open, []byte(""))
			if !bytes.Equal(open, out) {
				log.Println("IdP/sso: removed Response.InResponseTo")
			}
			return out
		})

		newXML := append(head, tail...)

		lastMu.Lock()
		lastPre = rr.Body.Bytes()
		lastPost = append([]byte{}, newXML...)
		lastMu.Unlock()

		newB64 := base64.StdEncoding.EncodeToString(newXML)
		body = append(body[:valStart], append([]byte(newB64), body[valStart+valEnd:]...)...)
		copyThrough(w, rr, body)
	})

	debugHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastMu.Lock()
		defer lastMu.Unlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("=== LAST SSO HTML (first 800 chars) ===\n"))
		if len(lastPre) > 0 {
			p := lastPre
			if len(p) > 800 {
				p = p[:800]
			}
			w.Write(p)
			w.Write([]byte("\n\n"))
		}
		w.Write([]byte("=== LAST SAML XML (post-strip) ===\n"))
		if len(lastPost) > 0 {
			w.Write(lastPost)
		} else {
			w.Write([]byte("(empty)\n"))
		}
	})

	must(createUsers(s))

	go func() {
		spMDURL, _ := url.Parse("http://web.heroctf.fr:8080/saml/metadata")
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			md, err := samlsp.FetchMetadata(ctx, http.DefaultClient, *spMDURL)
			cancel()
			if err == nil && md != nil {
				if len(md.SPSSODescriptors) > 0 {
					desc := &md.SPSSODescriptors[0]
					var filtered []saml.KeyDescriptor
					for _, kd := range desc.KeyDescriptors {
						if strings.EqualFold(kd.Use, "encryption") {
							continue
						}
						filtered = append(filtered, kd)
					}
					desc.KeyDescriptors = filtered
				}
				svc := &samlidp.Service{Name: "hero-sp", Metadata: *md}
				if err := s.Store.Put("/services/hero-sp", svc); err != nil {
					log.Printf("store service: %v", err)
				} else {
					log.Printf("registered SP metadata from %s (encryption keys stripped)", spMDURL)
				}
				return
			}
			time.Sleep(2 * time.Second)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/sso", ssoHandler)
	mux.HandleFunc("/debug/last-saml", debugHandler)
	mux.Handle("/", s)

	log.Printf("IdP listening on %s", idpURL)
	must(http.ListenAndServe(":8081", mux))
}

func copyThrough(w http.ResponseWriter, rr *httptest.ResponseRecorder, body []byte) {
	for k, vs := range rr.Header() {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rr.Code)
	_, _ = w.Write(body)
}
