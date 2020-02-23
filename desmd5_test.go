package hcrypto

import (
	"fmt"
	"testing"
)

// 测试 DES + MD5 加密解密
func TestDesMd5(t *testing.T) {
	k := "12345678"
	s := "你好12345678"

	// 加密
	encode, err := DesMd5Encode(s, k)
	if err != nil {
		fmt.Print(err)
	}
	t.Logf("encode=" + encode)

	// 解密
	decode, err := DesMd5Decode(encode, k)
	if err != nil {
		fmt.Print(err)
	}
	t.Logf("decode=" + decode)
}
