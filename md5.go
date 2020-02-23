package hcrypto

import (
	"crypto/md5"
	"encoding/hex"
)

// 32位字符串
func Md5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

// 16位字符串
func Md5Raw16(v string) string {
	str := Md5(v)
	return str[8:24]
}
