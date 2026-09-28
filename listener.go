package sslspoof

import (
	"net"
)

func NewListener(addr string, host string, md5 bool) (Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return Listener{}, err
	}

	return Listener{Listener: l, Host: host, MD5: md5}, nil
}

type Listener struct {
	net.Listener
	Host string
	MD5  bool
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		conn := &conn{Conn: c}

		err = conn.handshake(l.Host, l.MD5)
		if err != nil {
			c.Close()
			continue
		}

		return conn, nil
	}
}
