package sslspoof

import (
	"encoding/binary"
	"io"
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
