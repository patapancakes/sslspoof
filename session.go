package sslspoof

import (
	"bytes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
)

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

	r, err := readRecord(s.Conn)
	if err != nil {
		return 0, err
	}
	if r.Length < 1+md5.Size || 5+r.Length > 0x4000 {
		return 0, errors.New("invalid record length")
	}

	// decrypt record
	s.clientCipher.XORKeyStream(r.Fragment, r.Fragment)

	// if alert
	if r.ContentType == 0x15 {
		if r.Fragment[0] == 0x01 && r.Fragment[1] == 0x00 { // connection closed
			s.Close()
			return 0, io.EOF
		}

		return 0, errors.New("unhandled alert received")
	}

	// throw away the client MAC
	plaintext := r.Fragment[4 : len(r.Fragment)-md5.Size]

	// copy to b, buffer the rest
	n = copy(b, plaintext)
	if n < len(plaintext) {
		s.plaintext.Write(plaintext[n:])
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
