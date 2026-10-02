package sslspoof

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
)

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

	clientHello, err := readN[byte](c.Conn, clientHelloLen)
	if err != nil {
		return err
	}

	needsWeak := weakKey != nil
	var clientVersion []byte
	var clientRandom []byte

	if isSSL2 {
		ciphersLen := int(binary.BigEndian.Uint16(clientHello))
		if clientHelloLen < 6+ciphersLen {
			return errors.New("short client hello")
		}
		for chunk := range slices.Chunk(clientHello[6:6+ciphersLen], 3) {
			// look for SSL_RSA_WITH_RC4_128_MD5
			if bytes.Equal(chunk, []byte{0x00, 0x00, 0x04}) {
				needsWeak = false
				break
			}
		}

		clientVersion = clientHelloHeader[3:]
		clientRandom = clientHello[6+ciphersLen:]
		clientRandom = append(make([]byte, max(0, 32-len(clientRandom))), clientRandom...) // right justify
	} else {
		sessionLen := int(clientHello[38])
		if clientHelloLen < 39+sessionLen {
			return errors.New("short client hello")
		}

		ciphersLen := int(binary.BigEndian.Uint16(clientHello[39+sessionLen:]))
		if clientHelloLen < 39+sessionLen+2+ciphersLen {
			return errors.New("short client hello")
		}
		for chunk := range slices.Chunk(clientHello[39+sessionLen+2:39+sessionLen+2+ciphersLen], 2) {
			// look for SSL_RSA_WITH_RC4_128_MD5
			if bytes.Equal(chunk, []byte{0x00, 0x04}) {
				needsWeak = false
				break
			}
		}

		clientVersion = clientHello[4 : 4+1]
		clientRandom = clientHello[6 : 6+32]
	}

	finishHash.Write(clientHello)

	// Server Hello
	serverHello := []byte{
		0x16,       // content type (Handshake)
		0x03, 0x00, // version (SSLv3)
		0x00, 0x2A, // record length (42)
		0x02,             // handshake type (Server Hello)
		0x00, 0x00, 0x26, // length (38)
		0x03, 0x00, // version (SSLv3)
	}

	// server random
	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)
	serverHello = append(serverHello, serverRandom...)

	// session ID
	serverHello = append(serverHello, 0x00)

	// cipher suite
	cipherSuite := []byte{0x00, 0x04} // SSL_RSA_WITH_RC4_128_MD5
	if needsWeak {
		cipherSuite = []byte{0x00, 0x03} // SSL_RSA_EXPORT_WITH_RC4_40_MD5
	}

	serverHello = append(serverHello, cipherSuite...)

	// compression method
	serverHello = append(serverHello, 0x00) // NULL

	finishHash.Write(serverHello[5:])
	c.Conn.Write(serverHello)

	// Certificates
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
		0x16,       // content type (Handshake)
		0x03, 0x00, // version (SSLv3)
	}

	// length of record
	certificates = binary.BigEndian.AppendUint16(certificates, uint16(4+3+(len(certs)*3)+certsLen))

	// handshake type (Certificate)
	certificates = append(certificates, 0x0B)

	// length of handshake message
	certificates = appendUint24(certificates, uint32(3+(len(certs)*3)+certsLen))

	// length of certificates
	certificates = appendUint24(certificates, uint32((len(certs)*3)+certsLen))

	for _, cert := range certs {
		certificates = appendUint24(certificates, uint32(len(cert)))
		certificates = append(certificates, cert...)
	}

	finishHash.Write(certificates[5:])
	c.Conn.Write(certificates)

	// Server Hello Done
	serverHelloDone := []byte{
		0x16,       // content type (Handshake)
		0x03, 0x00, // version (SSLv3)
		0x00, 0x04, // record length (4)
		0x0E,             // handshake type (Server Hello Done)
		0x00, 0x00, 0x00, // length (0)
	}

	finishHash.Write(serverHelloDone[5:])
	c.Conn.Write(serverHelloDone)

	// Client Key Exchange
	clientKeyExchange, err := readRecord(c.Conn)
	if err != nil || len(clientKeyExchange.Fragment) < 4 {
		return errors.New("failed to read client key exchange")
	}

	encryptedPreMasterSecret := clientKeyExchange.Fragment[4:]
	finishHash.Write(clientKeyExchange.Fragment)

	// decrypt the pre master secret using our RSA key
	preMasterSecret, err := rsa.DecryptPKCS1v15(nil, certKey, encryptedPreMasterSecret)
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

	// create the MAC function and ciphers
	s.macFn = ssl30MAC{h: md5.New(), key: serverMAC}
	s.cipher, _ = rc4.NewCipher(serverKey)
	s.clientCipher, _ = rc4.NewCipher(clientKey)

	// (client) Change Cipher Spec
	_, err = readRecord(c.Conn)
	if err != nil {
		return errors.New("failed to read client change cipher spec")
	}

	// (client) Finished
	clientFinished, err := readRecord(c.Conn)
	if err != nil || len(clientFinished.Fragment) < md5.Size {
		return errors.New("failed to read client finished")
	}

	s.clientCipher.XORKeyStream(clientFinished.Fragment, clientFinished.Fragment)
	finishHash.Write(clientFinished.Fragment[:len(clientFinished.Fragment)-md5.Size])

	// (server) Change Cipher Spec
	c.Conn.Write([]byte{
		0x14,       // content type (Change Cipher Spec)
		0x03, 0x00, // version (SSLv3)
		0x00, 0x01, // record length (1)
		0x01, // Change Cipher Spec Message
	})

	// (server) Finished
	finished := []byte{
		0x16,       // content type (Handshake)
		0x03, 0x00, // version (SSLv3)
		0x00, 0x28, // record length (40)
	}
	finished, s.seq = encrypt(s.macFn, s.seq, s.cipher, append([]byte{
		0x14,             // handshake type (Finished)
		0x00, 0x00, 0x24, // length (36)
	}, finishHash.serverSum(masterSecret)...), finished)

	c.Conn.Write(finished)

	c.session = &s

	return nil
}
