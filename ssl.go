// modified from https://github.com/WiiLink24/wfc-server/blob/main/nas/tls.go
// licensed under GNU AFFERO GENERAL PUBLIC LICENSE Version 3, see LICENSE

package sslspoof

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"slices"
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

func mustParseCertificatePEM(b []byte) *x509.Certificate {
	certBlock, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		panic(err)
	}

	return cert
}

func mustParsePrivateKeyPEM(b []byte) *rsa.PrivateKey {
	keyBlock, _ := pem.Decode(b)
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	return key.(*rsa.PrivateKey)
}

var (
	intermediateCert = mustParseCertificatePEM(intermediateCertPEM)

	authorityCert = mustParseCertificatePEM(authorityCertPEM)
	authorityKey  = mustParsePrivateKeyPEM(authorityKeyPEM)
)

func GetServerCertsRecord(host string, md5 bool) ([]byte, error) {
	algo := x509.SHA1WithRSA
	if md5 {
		algo = x509.MD5WithRSA
	}

	cert, err := CreateCertificate(rand.Reader, &x509.Certificate{
		Subject:            pkix.Name{CommonName: host},
		NotBefore:          intermediateCert.NotBefore,
		NotAfter:           time.Now().UTC().Add(time.Hour * 24 * 365 * 5),
		SignatureAlgorithm: algo,
	}, authorityCert, &authorityKey.PublicKey, authorityKey)
	if err != nil {
		return nil, err
	}

	var b []byte
	b = []byte{
		0x16,       // Content Type (Handshake)
		0x03, 0x00, // Version (SSLv3)
	}

	certLen := len(cert)
	certLenCA := len(authorityCert.Raw) + len(intermediateCert.Raw)

	// Length of the record
	b = binary.BigEndian.AppendUint16(b, uint16(certLen+certLenCA+16))

	b = append(b, 0x0B) // Handshake Type (Certificate)

	// Length of handshake message
	b = append(b, 0x00) // padding byte to fit uint24
	b = binary.BigEndian.AppendUint16(b, uint16(certLen+certLenCA+12))

	// Length of certificates
	b = append(b, 0x00) // padding
	b = binary.BigEndian.AppendUint16(b, uint16(certLen+certLenCA+9))

	// Length of certificate (leaf)
	b = append(b, 0x00) // padding
	b = binary.BigEndian.AppendUint16(b, uint16(certLen))

	// Certificate data (leaf)
	b = append(b, cert...)

	// Length of certificate (authority)
	b = append(b, 0x00) // padding
	b = binary.BigEndian.AppendUint16(b, uint16(len(authorityCert.Raw)))

	// Certificate data (authority)
	b = append(b, authorityCert.Raw...)

	// Length of certificate (intermediate)
	b = append(b, 0x00) // padding
	b = binary.BigEndian.AppendUint16(b, uint16(len(intermediateCert.Raw)))

	// Certificate data (intermediate)
	b = append(b, intermediateCert.Raw...)

	b = append(b, []byte{
		0x16,       // Content Type (Handshake)
		0x03, 0x00, // Version (SSLv3)
		0x00, 0x04, // Length (4)
		0x0E,             // Handshake Type (Server Hello Done)
		0x00, 0x00, 0x00, // Length (0)
	}...)

	return b, nil
}

type conn struct {
	net.Conn
	handshaked bool
	session    io.ReadWriter
}

func (c *conn) Read(b []byte) (int, error) {
	return c.session.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	return c.session.Write(b)
}

func (c *conn) Close() error {
	if c.session != nil {
		conn, ok := c.session.(io.Closer)
		if ok {
			conn.Close()
		}
	}

	return c.Conn.Close()
}

// handshake handles the SSL request, and creates session for further communication.
func (c *conn) handshake(host string, useMD5 bool) error {
	in := make([]byte, 1400)
	n, err := c.Conn.Read(in)
	if err != nil {
		return fmt.Errorf("failed to read client hello: %w", err)
	}
	if n < 1 {
		return errors.New("short client hello")
	}

	clientHello := in[:n]

	var clientRandom []byte
	finishHash := newFinishedHash()

	if clientHello[0] == 0x80 { // SSLv2 Client Hello
		if n < 0x20 {
			return errors.New("short client hello")
		}

		clientRandom = clientHello[n-0x20:]
		finishHash.Write(clientHello[2:]) // skip length bytes
	} else { // SSLv3 Client Hello
		if n < 0x34 {
			return errors.New("short client hello")
		}

		clientRandom = clientHello[0x0b : 0x0b+0x20]
		finishHash.Write(clientHello[0x5:0x34])
	}

	serverHello := []byte{
		0x16,       // Content Type (Handshake)
		0x03, 0x00, // Version (SSLv3)
		0x00, 0x2A, // Length (42)
		0x02,             // Handshake Type (Server Hello)
		0x00, 0x00, 0x26, // Length (38)
		0x03, 0x00, // Version (SSLv3)
	}

	serverRandom := make([]byte, 0x20)
	_, err = rand.Read(serverRandom)
	if err != nil {
		return fmt.Errorf("failed to generate random bytes: %w", err)
	}

	serverHello = append(serverHello, serverRandom...)

	// Send an empty session ID
	serverHello = append(serverHello, 0x00)

	// Select cipher suite and compression method
	serverHello = append(serverHello, []byte{
		0x00, 0x04, // Cipher Suite (SSL_RSA_WITH_RC4_128_MD5)
		0x00, // Compression Method (NULL)
	}...)

	scr, err := GetServerCertsRecord(host, useMD5)
	if err != nil {
		return err
	}

	// Append the certs record to the server hello buffer
	serverHello = append(serverHello, scr...)

	finishHash.Write(serverHello[0x5:0x2F])
	finishHash.Write(serverHello[0x34 : 0x34+(len(scr)-14)])
	finishHash.Write(serverHello[0x34+(len(scr)-14)+5 : 0x34+(len(scr)-14)+5+4])

	_, err = c.Conn.Write(serverHello)
	if err != nil {
		return fmt.Errorf("failed to write to client: %w", err)
	}

	buf := make([]byte, 0x1000)
	index := 0
	// Read client key exchange (+ change cipher spec + finished)
	for {
		var n int
		n, err = c.Conn.Read(buf[index:])
		if err != nil {
			return fmt.Errorf("failed to read key exchange: %w", err)
		}

		index += n

		if index > 0x09 {
			// Check client key exchange header
			if !bytes.HasPrefix(buf, []byte{
				0x16,       // Content Type (Handshake)
				0x03, 0x00, // Version (SSLv3)
				0x00, 0x84, // Length (132)
				0x10,             // Handshake Type (Client Key Exchange)
				0x00, 0x00, 0x80, // Length (128)
			}) {
				return errors.New("invalid client key exchange header")
			}
		}

		if index > 0x8B {
			// Check change cipher spec + finished header
			if !bytes.HasPrefix(buf[0x89:], []byte{
				0x14,       // Content Type (Change Cipher Spec)
				0x03, 0x00, // Version (SSLv3)
				0x00, 0x01, // Length (1)
				0x01, // Change Cipher Spec Message

				0x16,       // Content Type (Handshake)
				0x03, 0x00, // Version (SSLv3)
				0x00, 0x38, // Length (56)
			}) {
				return errors.New("invalid client change cipher spec + finished header")
			}
		}

		if index == 0xCC {
			buf = buf[:index]
			break
		}

		if index > 0xCC {
			return errors.New("invalid client key exchange length")
		}
	}

	encryptedPreMasterSecret := buf[0x09 : 0x09+0x80]
	clientFinish := buf[0x94 : 0x94+0x38]

	finishHash.Write(buf[0x5 : 0x5+0x84])

	// Decrypt the pre master secret using our RSA key
	preMasterSecret, err := rsa.DecryptPKCS1v15(rand.Reader, authorityKey, encryptedPreMasterSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt pre master secret: %w", err)
	}

	if len(preMasterSecret) != 48 {
		return errors.New("invalid pre master secret length")
	}

	if !bytes.HasPrefix(preMasterSecret, []byte{0x03, 0x00}) {
		return errors.New("invalid SSL version in pre master secret")
	}

	clientServerRandom := append(bytes.Clone(clientRandom), serverRandom[:0x20]...)

	masterSecret := make([]byte, 48)
	prf30(masterSecret, preMasterSecret, []byte("master secret"), clientServerRandom)

	_, serverMAC, clientKey, serverKey, _, _ := keysFromMasterSecret(masterSecret, clientRandom, serverRandom, md5.Size, 16, 16)

	// Create the server RC4 cipher
	cipher, err := rc4.NewCipher(serverKey)
	if err != nil {
		return err
	}

	// Create the client RC4 cipher
	clientCipher, err := rc4.NewCipher(clientKey)
	if err != nil {
		return err
	}

	// Create the mac function
	macFn := ssl30MAC{
		h:   md5.New(),
		key: slices.Clone(serverMAC),
	}

	// Decrypt client finish
	clientCipher.XORKeyStream(clientFinish, clientFinish)
	finishHash.Write(clientFinish[:0x28])

	// Send ChangeCipherSpec
	_, err = c.Conn.Write([]byte{
		0x14,       // Content Type (Change Cipher Spec)
		0x03, 0x00, // Version (SSLv3)
		0x00, 0x01, // Length (1)
		0x01, // Change Cipher Spec Message
	})
	if err != nil {
		return err
	}

	finishedRecord := []byte{
		0x16,       // Content Type (Handshake)
		0x03, 0x00, // Version (SSLv3)
		0x00, 0x28, // Length (40)
	}

	out := finishHash.serverSum(masterSecret)

	// Encrypt the finished record
	finishedRecord, _ = encryptSSL(macFn, cipher, append([]byte{
		0x14,             // Handshake Type (Finished)
		0x00, 0x00, 0x24, // Length (36)
	}, out[:36]...), 0, finishedRecord)

	_, err = c.Conn.Write(finishedRecord)
	if err != nil {
		return err
	}

	c.session = &session{
		Conn:         c.Conn,
		macFn:        macFn,
		cipher:       cipher,
		clientCipher: clientCipher,
		seq:          1,
	}
	c.handshaked = true

	return nil
}

type session struct {
	net.Conn
	bufferSize    int
	macFn         macFunction
	cipher        *rc4.Cipher
	clientCipher  *rc4.Cipher
	seq           uint64
	decodedBuffer bytes.Buffer
	encodedBuffer bytes.Buffer
}

func (s *session) Read(b []byte) (n int, err error) {
	if s.decodedBuffer.Len() != 0 {
		return s.decodedBuffer.Read(b)
	}

	var recordLength uint16
	for {
		for s.encodedBuffer.Len() < int(recordLength)+5 {
			readBuf := make([]byte, 1024)
			n, err = s.Conn.Read(readBuf)
			if err != nil {
				return 0, err
			}

			s.encodedBuffer.Write(readBuf[:n])
		}

		buf := s.encodedBuffer.Bytes()
		if buf[0] < 0x15 || buf[0] > 0x17 {
			return 0, errors.New("invalid record type")
		}

		if !bytes.Equal(buf[1:3], []byte{0x03, 0x00}) {
			return 0, errors.New("invalid SSL version")
		}

		recordLength = binary.BigEndian.Uint16(buf[3:])
		if recordLength < 1+md5.Size || (recordLength+5) > 0x1000 {
			return 0, errors.New("invalid record length")
		}

		if s.encodedBuffer.Len() >= int(recordLength)+5 {
			break
		}
	}

	buf := s.encodedBuffer.Bytes()
	// Decrypt content
	s.clientCipher.XORKeyStream(buf[5:5+recordLength], buf[5:5+recordLength])

	if buf[0] != 0x17 {
		if buf[0] == 0x15 || buf[5] == 0x01 || buf[6] == 0x00 {
			// Alert: connection closed
			err = s.Close()
			if err != nil {
				return 0, err
			}

			return 0, io.EOF
		}

		return 0, errors.New("non-application data received")
	}

	// Write the decrypted content to the buffer
	if int(recordLength-md5.Size) > len(b) {
		s.decodedBuffer.Write(buf[5+len(b) : 5+recordLength-md5.Size])
	}

	s.encodedBuffer.Next(5 + int(recordLength))

	return copy(b, buf[5:5+recordLength-md5.Size]), nil
}

func (s *session) Write(b []byte) (n int, err error) {
	record := []byte{0x17, 0x03, 0x00}
	record = binary.BigEndian.AppendUint16(record, uint16(len(b)))

	record, s.seq = encryptSSL(s.macFn, s.cipher, b, s.seq, record)
	return s.Conn.Write(record)
}

// The following functions are modified from the crypto standard library
//
// Copyright (c) 2009 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// prf30 implements the SSLv3 pseudo-random function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 6.
func prf30(result, secret, label, seed []byte) {
	hashSHA1 := sha1.New()
	hashMD5 := md5.New()

	done := 0
	i := 0
	// RFC5246 section 6.3 says that the largest PRF output needed is 128
	// bytes. Since no more ciphersuites will be added to SSLv3, this will
	// remain true. Each iteration gives us 16 bytes so 10 iterations will
	// be sufficient.
	var b [11]byte
	for done < len(result) {
		for j := 0; j <= i; j++ {
			b[j] = 'A' + byte(i)
		}

		hashSHA1.Reset()
		hashSHA1.Write(b[:i+1])
		hashSHA1.Write(secret)
		hashSHA1.Write(seed)
		digest := hashSHA1.Sum(nil)

		hashMD5.Reset()
		hashMD5.Write(secret)
		hashMD5.Write(digest)

		done += copy(result[done:], hashMD5.Sum(nil))
		i++
	}
}

// keysFromMasterSecret generates the connection keys from the master
// secret, given the lengths of the MAC key, cipher key and IV, as defined in
// RFC 2246, Section 6.3.
func keysFromMasterSecret(masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*macLen + 2*keyLen + 2*ivLen
	keyMaterial := make([]byte, n)
	prf30(keyMaterial, masterSecret, []byte("key expansion"), seed)
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]
	return
}

func newFinishedHash() finishedHash {
	return finishedHash{sha1.New(), sha1.New(), md5.New(), md5.New()}
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type finishedHash struct {
	client hash.Hash
	server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	clientMD5 hash.Hash
	serverMD5 hash.Hash
}

func (h *finishedHash) Write(msg []byte) int {
	h.client.Write(msg)
	h.server.Write(msg)

	h.clientMD5.Write(msg)
	h.serverMD5.Write(msg)

	return len(msg)
}

// finishedSum30 calculates the contents of the verify_data member of a SSLv3
// Finished message given the MD5 and SHA1 hashes of a set of handshake
// messages.
func finishedSum30(md5, sha1 hash.Hash, masterSecret []byte, magic [4]byte) []byte {
	md5.Write(magic[:])
	md5.Write(masterSecret)
	md5.Write(ssl30Pad1[:])
	md5Digest := md5.Sum(nil)

	md5.Reset()
	md5.Write(masterSecret)
	md5.Write(ssl30Pad2[:])
	md5.Write(md5Digest)
	md5Digest = md5.Sum(nil)

	sha1.Write(magic[:])
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad1[:40])
	sha1Digest := sha1.Sum(nil)

	sha1.Reset()
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad2[:40])
	sha1.Write(sha1Digest)
	sha1Digest = sha1.Sum(nil)

	ret := make([]byte, len(md5Digest)+len(sha1Digest))
	copy(ret, md5Digest)
	copy(ret[len(md5Digest):], sha1Digest)
	return ret
}

// serverSum returns the contents of the verify_data member of a server's
// Finished message.
func (h finishedHash) serverSum(masterSecret []byte) []byte {
	return finishedSum30(h.serverMD5, h.server, masterSecret, [4]byte{0x53, 0x52, 0x56, 0x52})
}

func encryptSSL(macFn macFunction, cipher *rc4.Cipher, payload []byte, seq uint64, record []byte) ([]byte, uint64) {
	mac := macFn.MAC([]byte{}, binary.BigEndian.AppendUint64([]byte{}, seq), record[:5], payload, nil)

	record = append(append(bytes.Clone(record[:5]), payload...), mac...)
	cipher.XORKeyStream(record[5:], record[5:])

	// Update length to include nonce, MAC and any block padding needed.
	binary.BigEndian.PutUint16(record[3:], uint16(len(record)-5))

	return record, seq + 1
}

type macFunction interface {
	MAC(out, seq, header, data, extra []byte) []byte
}

// ssl30MAC implements the SSLv3 MAC function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 5.2.3.1
type ssl30MAC struct {
	h   hash.Hash
	key []byte
}

var ssl30Pad1 = [48]byte{0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}

var ssl30Pad2 = [48]byte{0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}

func (s ssl30MAC) MAC(out, seq, header, data []byte, extra []byte) []byte {
	padLength := 48
	if s.h.Size() == sha1.Size {
		padLength = 40
	}

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad1[:padLength])
	s.h.Write(seq)
	s.h.Write(header[:1])
	s.h.Write(header[3:5])
	s.h.Write(data)
	out = s.h.Sum(out[:0])

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad2[:padLength])
	s.h.Write(out)
	return s.h.Sum(out[:0])
}
