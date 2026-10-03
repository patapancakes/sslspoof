package sslspoof

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"time"

	_ "embed"
)

var (
	//go:embed data/intermediate.crt
	intermediateCertPEM []byte

	//go:embed data/authority.crt
	authorityCertPEM []byte
	//go:embed data/authority.key
	authorityKeyPEM []byte
)

func parseCertificatePEM(b []byte) *x509.Certificate {
	certBlock, _ := pem.Decode(b)
	cert, _ := x509.ParseCertificate(certBlock.Bytes)
	return cert
}

func parseKeyPEM(b []byte) *rsa.PrivateKey {
	keyBlock, _ := pem.Decode(b)
	key, _ := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	return key.(*rsa.PrivateKey)
}

var (
	intermediateCert = parseCertificatePEM(intermediateCertPEM)

	authorityCert = parseCertificatePEM(authorityCertPEM)
	authorityKey  = parseKeyPEM(authorityKeyPEM)

	weakKey, _ = rsa.GenerateKey(rand.Reader, 512)
)

func NewListener(addr string, host string, md5 bool) (*Listener, error) {
	var l Listener
	var err error

	l.Listener, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"sslspoof"},
			OrganizationalUnit: []string{"pancakes at mooglepowered dot com"},
			CommonName:         host,
		},
		NotBefore:          intermediateCert.NotBefore,
		NotAfter:           time.Now().UTC().Add(time.Hour * 24 * 365 * 5),
		SignatureAlgorithm: x509.SHA1WithRSA,
	}
	if md5 {
		template.SignatureAlgorithm = x509.MD5WithRSA
	}

	l.cert, err = createCertificate(rand.Reader, &template, authorityCert, &authorityKey.PublicKey, authorityKey)
	if err != nil {
		return nil, err
	}

	if weakKey != nil {
		l.weakCert, err = createCertificate(rand.Reader, &template, authorityCert, &weakKey.PublicKey, authorityKey)
		if err != nil {
			return nil, err
		}
	}

	return &l, nil
}

type Listener struct {
	net.Listener
	cert, weakCert []byte
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		conn := Conn{Conn: c, listener: l}

		err = conn.handshake()
		if err != nil {
			c.Close()
			continue
		}

		return &conn, err
	}
}
