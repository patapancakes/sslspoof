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
	"strconv"
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

	certs = make(map[string][]byte) // TODO: make thread-safe
)

func read[T any](r io.Reader) (T, error) {
	var value T

	err := binary.Read(r, binary.BigEndian, &value)
	return value, err
}

func readN[T any](r io.Reader, n int) ([]T, error) {
	value := make([]T, n)

	err := binary.Read(r, binary.BigEndian, &value)
	return value, err
}

func appendUint24(b []byte, v uint32) []byte {
	return append(b,
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}

type conn struct {
	net.Conn
	session io.ReadWriter
}

func (c *conn) Read(b []byte) (int, error) {
	return c.session.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	return c.session.Write(b)
}

// handshake handles the SSL request, and creates session for further communication.
func (c *conn) handshake(host string, useMD5 bool) error {
	// Client Hello
	clientHelloHeader, err := readN[byte](c.Conn, 5)
	if err != nil {
		return err
	}

	isSSL2 := clientHelloHeader[0] == 0x80
	finishHash := newFinishedHash()

	var clientHelloLen int
	if isSSL2 {
		clientHelloLen = int(clientHelloHeader[1])
		if clientHelloLen < 0x20 {
			return errors.New("short client hello")
		}

		// taken by clientHelloHeader
		clientHelloLen -= 3

		finishHash.Write(clientHelloHeader[2:])
	} else {
		clientHelloLen = int(binary.BigEndian.Uint16(clientHelloHeader[3:]))
		if clientHelloLen < 0x34 {
			return errors.New("short client hello")
		}
	}

	clientHelloBody, err := readN[byte](c.Conn, clientHelloLen)
	if err != nil {
		return err
	}

	needsExport := true
	var clientVersion []byte
	var clientRandom []byte

	if isSSL2 {
		ciphersLen := binary.BigEndian.Uint16(clientHelloBody)
		if clientHelloLen < 6+int(ciphersLen) {
			return errors.New("short client hello")
		}
		for chunk := range slices.Chunk(clientHelloBody[6:6+ciphersLen], 3) {
			// look for SSL_RSA_WITH_RC4_128_MD5
			if bytes.Equal(chunk, []byte{0x00, 0x00, 0x04}) {
				needsExport = false
				break
			}
		}

		clientVersion = clientHelloHeader[3:]
		clientRandom = clientHelloBody[6+ciphersLen:]
		clientRandom = append(make([]byte, max(0, 32-len(clientRandom))), clientRandom...) // right justify
	} else {
		ciphersLen := binary.BigEndian.Uint16(clientHelloBody[39:])
		if clientHelloLen < 39+2+int(ciphersLen) {
			return errors.New("short client hello")
		}
		for chunk := range slices.Chunk(clientHelloBody[39+2:39+2+ciphersLen], 2) {
			// look for SSL_RSA_WITH_RC4_128_MD5
			if bytes.Equal(chunk, []byte{0x00, 0x04}) {
				needsExport = false
				break
			}
		}

		clientVersion = clientHelloBody[4 : 4+1]
		clientRandom = clientHelloBody[6 : 6+32]
	}

	finishHash.Write(clientHelloBody)

	// Server Hello
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

	// Select cipher suite
	cipherSuite := []byte{0x00, 0x04} // SSL_RSA_WITH_RC4_128_MD5
	if needsExport {
		cipherSuite = []byte{0x00, 0x03} // SSL_RSA_EXPORT_WITH_RC4_40_MD5
	}

	serverHello = append(serverHello, cipherSuite...)

	// Select compression method
	serverHello = append(serverHello, 0x00) // NULL

	finishHash.Write(serverHello[5:])
	c.Conn.Write(serverHello)

	// Server Certificates
	certKey := authorityKey
	if needsExport {
		certKey = weakKey
	}

	cert, ok := certs[host+strconv.Itoa(certKey.PublicKey.Size())]
	if !ok {
		algo := x509.SHA1WithRSA
		if useMD5 {
			algo = x509.MD5WithRSA
		}

		cert, err = createCertificate(rand.Reader, &x509.Certificate{
			Subject:            pkix.Name{CommonName: host},
			NotBefore:          intermediateCert.NotBefore,
			NotAfter:           time.Now().UTC().Add(time.Hour * 24 * 365 * 5),
			SignatureAlgorithm: algo,
		}, authorityCert, &certKey.PublicKey, authorityKey)
		if err != nil {
			return err
		}

		certs[host+strconv.Itoa(certKey.PublicKey.Size())] = cert
	}

	certs := [][]byte{cert, authorityCert.Raw, intermediateCert.Raw}

	var certsLen int
	for _, cert := range certs {
		certsLen += len(cert)
	}

	certificates := []byte{
		0x16,       // Content Type (Handshake)
		0x03, 0x00, // Version (SSLv3)
	}

	// Length of the record
	certificates = binary.BigEndian.AppendUint16(certificates, uint16(1+3+3+(len(certs)*3)+certsLen))

	certificates = append(certificates, 0x0B) // Handshake Type (Certificate)

	// Length of handshake message
	certificates = appendUint24(certificates, uint32(3+(len(certs)*3)+certsLen))

	// Length of certificates
	certificates = appendUint24(certificates, uint32((len(certs)*3)+certsLen))

	for _, cert := range certs {
		certificates = appendUint24(certificates, uint32(len(cert)))
		certificates = append(certificates, cert...)
	}

	finishHash.Write(certificates[5:])
	c.Conn.Write(certificates)

	// Server Hello Done
	serverHelloDone := []byte{
		0x16,       // Content Type (Handshake)
		0x03, 0x00, // Version (SSLv3)
		0x00, 0x04, // Length (4)
		0x0E,             // Handshake Type (Server Hello Done)
		0x00, 0x00, 0x00, // Length (0)
	}

	finishHash.Write(serverHelloDone[5:])
	c.Conn.Write(serverHelloDone)

	// Client Key Exchange
	clientKeyExchange, err := readN[byte](c.Conn, 5+4+certKey.PublicKey.Size())
	if err != nil {
		return errors.New("failed to read client key exchange")
	}
	if !bytes.HasPrefix(clientKeyExchange, []byte{
		0x16,       // Content Type (Handshake)
		0x03, 0x00, // Version (SSLv3)
		0x00, byte(4 + certKey.PublicKey.Size()), // Length (4 + RSA Key Size)
		0x10,                                       // Handshake Type (Client Key Exchange)
		0x00, 0x00, byte(certKey.PublicKey.Size()), // Length (RSA Key Size)
	}) {
		return errors.New("invalid client key exchange header")
	}

	encryptedPreMasterSecret := clientKeyExchange[5+4:]
	finishHash.Write(clientKeyExchange[5:])

	// Client Change Cipher Spec
	changeCipherSpec, err := readN[byte](c.Conn, 5+1)
	if err != nil {
		return errors.New("failed to read client change cipher spec")
	}
	if !bytes.HasPrefix(changeCipherSpec, []byte{
		0x14,       // Content Type (Change Cipher Spec)
		0x03, 0x00, // Version (SSLv3)
		0x00, 0x01, // Length (1)
		0x01, // Change Cipher Spec Message
	}) {
		return errors.New("invalid client change cipher spec")
	}

	// Client Finished
	finished, err := readN[byte](c.Conn, 5+4+md5.Size+sha1.Size+md5.Size)
	if err != nil {
		return errors.New("failed to read client finished")
	}
	if !bytes.HasPrefix(finished, []byte{
		0x16,       // Content Type (Handshake)
		0x03, 0x00, // Version (SSLv3)
		0x00, 0x38, // Length (56)
	}) {
		return errors.New("invalid client finished header")
	}

	clientFinish := finished[5:]

	// Decrypt the pre master secret using our RSA key
	preMasterSecret, err := rsa.DecryptPKCS1v15(rand.Reader, certKey, encryptedPreMasterSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt pre master secret: %w", err)
	}
	if len(preMasterSecret) != 48 {
		return errors.New("invalid pre master secret length")
	}
	if !bytes.HasPrefix(preMasterSecret, clientVersion) {
		return errors.New("invalid ssl version in pre master secret")
	}

	masterSecret := make([]byte, 48)
	prf30(masterSecret, preMasterSecret, []byte("master secret"), append(clientRandom, serverRandom...))

	keyLen := 16 // 128-bit
	if needsExport {
		keyLen = 5 // 40-bit
	}

	_, serverMAC, clientKey, serverKey, _, _ := keysFromMasterSecret(masterSecret, clientRandom, serverRandom, md5.Size, keyLen, 0)
	if needsExport {
		clientKey = exportRC4Key(clientKey, clientRandom, serverRandom, true)
		serverKey = exportRC4Key(serverKey, clientRandom, serverRandom, false)
	}

	s := session{Conn: c.Conn}

	// Create the MAC function
	s.macFn = ssl30MAC{
		h:   md5.New(),
		key: slices.Clone(serverMAC),
	}

	// Create the server RC4 cipher
	s.cipher, err = rc4.NewCipher(serverKey)
	if err != nil {
		return err
	}

	// Create the client RC4 cipher
	s.clientCipher, err = rc4.NewCipher(clientKey)
	if err != nil {
		return err
	}

	// Decrypt client Finished
	s.clientCipher.XORKeyStream(clientFinish, clientFinish)
	finishHash.Write(clientFinish[:len(clientFinish)-md5.Size])

	// Server Change Cipher Spec
	c.Conn.Write([]byte{
		0x14,       // Content Type (Change Cipher Spec)
		0x03, 0x00, // Version (SSLv3)
		0x00, 0x01, // Length (1)
		0x01, // Change Cipher Spec Message
	})

	// Server Finished
	finishedRecord := []byte{
		0x16,       // Content Type (Handshake)
		0x03, 0x00, // Version (SSLv3)
		0x00, 0x28, // Length (40)
	}

	// Encrypt server Finished record
	finishedRecord, s.seq = encrypt(s.macFn, s.cipher, append([]byte{
		0x14,             // Handshake Type (Finished)
		0x00, 0x00, 0x24, // Length (36)
	}, finishHash.serverSum(masterSecret)...), s.seq, finishedRecord)

	c.Conn.Write(finishedRecord)

	c.session = &s

	return nil
}

func exportRC4Key(key, clientRandom, serverRandom []byte, client bool) []byte {
	b := bytes.Clone(key)
	if client {
		b = append(b, clientRandom...)
		b = append(b, serverRandom...)
	} else {
		b = append(b, serverRandom...)
		b = append(b, clientRandom...)
	}

	sum := md5.Sum(b)
	return sum[:]
}

type session struct {
	net.Conn
	macFn        macFunction
	cipher       *rc4.Cipher
	clientCipher *rc4.Cipher
	seq          uint64
	plaintext    bytes.Buffer
}

func (s *session) Read(b []byte) (n int, err error) {
	if s.plaintext.Len() != 0 {
		return s.plaintext.Read(b)
	}

	recordType, err := read[byte](s.Conn)
	if err != nil {
		return 0, err
	}
	if recordType != 0x15 && recordType != 0x17 {
		return 0, errors.New("invalid record type")
	}

	version, err := readN[byte](s.Conn, 2)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(version, []byte{0x03, 0x00}) {
		return 0, errors.New("invalid ssl version")
	}

	recordLen, err := read[uint16](s.Conn)
	if err != nil {
		return 0, err
	}
	if recordLen < 1+md5.Size || 5+recordLen > 0x4000 {
		return 0, errors.New("invalid record length")
	}

	record, err := readN[byte](s.Conn, int(recordLen))
	if err != nil {
		return 0, err
	}

	// decrypt record
	s.clientCipher.XORKeyStream(record, record)

	// if alert
	if recordType == 0x15 {
		if record[0] == 0x01 && record[1] == 0x00 { // connection closed
			s.Close()
			return 0, io.EOF
		}

		return 0, errors.New("unhandled alert received")
	}

	// throw away the client MAC
	data := record[:recordLen-md5.Size]

	// copy to b, buffer the rest
	n = copy(b, data)
	if n < len(data) {
		s.plaintext.Write(data[n:])
	}

	return n, nil
}

func (s *session) Write(b []byte) (n int, err error) {
	var written int
	for chunk := range slices.Chunk(b, 0x4000-5-md5.Size) {
		record := []byte{0x17, 0x03, 0x00}
		record = binary.BigEndian.AppendUint16(record, uint16(len(chunk)))

		record, s.seq = encrypt(s.macFn, s.cipher, chunk, s.seq, record)
		_, err := s.Conn.Write(record)
		if err != nil {
			return written, err
		}

		written += len(chunk)
	}

	return written, nil
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

func encrypt(macFn macFunction, cipher *rc4.Cipher, payload []byte, seq uint64, record []byte) ([]byte, uint64) {
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
