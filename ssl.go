package sslspoof

import (
	"bytes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"slices"
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
	listener *Listener
	session  io.ReadWriter
}

func (c *conn) Read(b []byte) (int, error) {
	return c.session.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	return c.session.Write(b)
}

// handshake handles the SSL request, and creates session for further communication.
func (c *conn) handshake() error {
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

	needsWeak := weakKey != nil
	var clientVersion []byte
	var clientRandom []byte

	if isSSL2 {
		ciphersLen := int(binary.BigEndian.Uint16(clientHelloBody))
		if clientHelloLen < 6+ciphersLen {
			return errors.New("short client hello")
		}
		for chunk := range slices.Chunk(clientHelloBody[6:6+ciphersLen], 3) {
			// look for SSL_RSA_WITH_RC4_128_MD5
			if bytes.Equal(chunk, []byte{0x00, 0x00, 0x04}) {
				needsWeak = false
				break
			}
		}

		clientVersion = clientHelloHeader[3:]
		clientRandom = clientHelloBody[6+ciphersLen:]
		clientRandom = append(make([]byte, max(0, 32-len(clientRandom))), clientRandom...) // right justify
	} else {
		sessionLen := int(clientHelloBody[38])
		if clientHelloLen < 39+sessionLen {
			return errors.New("short client hello")
		}

		ciphersLen := int(binary.BigEndian.Uint16(clientHelloBody[39+sessionLen:]))
		if clientHelloLen < 39+sessionLen+2+ciphersLen {
			return errors.New("short client hello")
		}
		for chunk := range slices.Chunk(clientHelloBody[39+sessionLen+2:39+sessionLen+2+ciphersLen], 2) {
			// look for SSL_RSA_WITH_RC4_128_MD5
			if bytes.Equal(chunk, []byte{0x00, 0x04}) {
				needsWeak = false
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

	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)
	serverHello = append(serverHello, serverRandom...)

	// Send an empty session ID
	serverHello = append(serverHello, 0x00)

	// Select cipher suite
	cipherSuite := []byte{0x00, 0x04} // SSL_RSA_WITH_RC4_128_MD5
	if needsWeak {
		cipherSuite = []byte{0x00, 0x03} // SSL_RSA_EXPORT_WITH_RC4_40_MD5
	}

	serverHello = append(serverHello, cipherSuite...)

	// Select compression method
	serverHello = append(serverHello, 0x00) // NULL

	finishHash.Write(serverHello[5:])
	c.Conn.Write(serverHello)

	// Server Certificates
	cert := c.listener.cert
	certKey := authorityKey
	if needsWeak {
		cert = c.listener.weakCert
		certKey = weakKey
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
	certificates = binary.BigEndian.AppendUint16(certificates, uint16(4+3+(len(certs)*3)+certsLen))

	// Handshake Type (Certificate)
	certificates = append(certificates, 0x0B)

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

	encryptedPreMasterSecret := clientKeyExchange[5+4:]
	finishHash.Write(clientKeyExchange[5:])

	// Decrypt the pre master secret using our RSA key
	preMasterSecret, err := rsa.DecryptPKCS1v15(rand.Reader, certKey, encryptedPreMasterSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt pre master secret: %w", err)
	}
	if len(preMasterSecret) != 48 || !bytes.HasPrefix(preMasterSecret, clientVersion) {
		return errors.New("invalid pre master secret")
	}

	masterSecret := make([]byte, 48)
	prf30(masterSecret, preMasterSecret, []byte("master secret"), append(clientRandom, serverRandom...))

	keyLen := 16 // 128-bit
	if needsWeak {
		keyLen = 5 // 40-bit
	}

	_, serverMAC, clientKey, serverKey, _, _ := keysFromMasterSecret(masterSecret, clientRandom, serverRandom, md5.Size, keyLen, 0)
	if needsWeak {
		clientKey = exportRC4Key(clientKey, clientRandom, serverRandom, true)
		serverKey = exportRC4Key(serverKey, clientRandom, serverRandom, false)
	}

	s := session{Conn: c.Conn}

	// Create the MAC function
	s.macFn = ssl30MAC{h: md5.New(), key: serverMAC}

	// Create the RC4 ciphers
	s.cipher, _ = rc4.NewCipher(serverKey)
	s.clientCipher, _ = rc4.NewCipher(clientKey)

	// Client Change Cipher Spec
	_, err = readN[byte](c.Conn, 5+1)
	if err != nil {
		return errors.New("failed to read client change cipher spec")
	}

	// Client Finished
	clientFinished, err := readN[byte](c.Conn, 5+4+md5.Size+sha1.Size+md5.Size)
	if err != nil {
		return errors.New("failed to read client finished")
	}

	clientFinish := clientFinished[5:]

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
	finished := []byte{
		0x16,       // Content Type (Handshake)
		0x03, 0x00, // Version (SSLv3)
		0x00, 0x28, // Length (40)
	}
	finished, s.seq = encrypt(s.macFn, s.seq, s.cipher, append([]byte{
		0x14,             // Handshake Type (Finished)
		0x00, 0x00, 0x24, // Length (36)
	}, finishHash.serverSum(masterSecret)...), finished)

	c.Conn.Write(finished)

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
	cipher, clientCipher cipher.Stream
	macFn                macFunction
	seq                  uint64
	plaintext            bytes.Buffer
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

		record, s.seq = encrypt(s.macFn, s.seq, s.cipher, chunk, record)
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
	return finishedSum30(h.serverMD5, h.server, masterSecret, [4]byte{'S', 'R', 'V', 'R'})
}

func encrypt(macFn macFunction, seq uint64, cipher cipher.Stream, payload []byte, record []byte) ([]byte, uint64) {
	payload = append(payload, macFn.MAC(nil, binary.BigEndian.AppendUint64(nil, seq), record, payload, nil)...)

	cipher.XORKeyStream(payload, payload)

	binary.BigEndian.PutUint16(record[3:], uint16(len(payload)))
	record = append(record, payload...)

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
