package sslspoof

import (
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
)

var oidMD5WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}

// workaround since x509.createCertificate disallows MD5WithRSA signatures
func createCertificate(rand io.Reader, template, parent *x509.Certificate, pub, priv any) ([]byte, error) {
	t := *template

	isMD5 := template.SignatureAlgorithm == x509.MD5WithRSA
	if isMD5 {
		t.SignatureAlgorithm = x509.SHA1WithRSA
	}

	der, err := x509.CreateCertificate(rand, &t, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	if !isMD5 {
		return der, nil
	}

	var cert struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return nil, err
	}

	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(cert.TBS.FullBytes, &tbs); err != nil {
		return nil, err
	}

	var fields []asn1.RawValue
	for data := tbs.Bytes; len(data) > 0; {
		var field asn1.RawValue
		var err error
		data, err = asn1.Unmarshal(data, &field)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}

	algorithm, _ := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm:  oidMD5WithRSA,
		Parameters: asn1.NullRawValue,
	})
	fields[2] = asn1.RawValue{FullBytes: algorithm}

	var content []byte
	for _, field := range fields {
		content = append(content, field.FullBytes...)
	}

	tbsDER, err := asn1.Marshal(asn1.RawValue{
		Tag:        16,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		return nil, err
	}

	digest := md5.Sum(tbsDER)
	signature, err := rsa.SignPKCS1v15(rand, priv.(*rsa.PrivateKey), crypto.MD5, digest[:])
	if err != nil {
		return nil, err
	}

	cert.TBS.FullBytes = tbsDER
	cert.Algorithm = pkix.AlgorithmIdentifier{
		Algorithm:  oidMD5WithRSA,
		Parameters: asn1.NullRawValue,
	}
	cert.Signature = asn1.BitString{
		Bytes:     signature,
		BitLength: len(signature) * 8,
	}

	return asn1.Marshal(cert)
}
