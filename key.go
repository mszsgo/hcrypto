package hencrypt

import (
	"crypto/sha1"
)

func KeyGenerator(src []byte, blockSize int) []byte {
	hashs := SHA1(SHA1(src))
	maxLen := len(hashs)
	if blockSize > maxLen {
		return src
	}

	return hashs[0:blockSize]
}

func SHA1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}
