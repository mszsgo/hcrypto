package hencrypt

import (
	"crypto/md5"
	"encoding/hex"
)

// Md5
func Md5(v string) (d string) {
	h := md5.New()
	h.Write([]byte(v))
	d = hex.EncodeToString(h.Sum(nil))
	return d
}
