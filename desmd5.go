package hcrypto

import (
	"encoding/base64"
	"errors"
)

/*
对称加密（DES）+验签（MD5）方式方法如下：
加密步骤：
  1. 【加密报文】通过双方约定的密钥K1使用DES加密报文明文S1，得到密文字节数组B1;
  2. 【加密报文】取得密文字节数组的Base64表示形式S2;
  3. 【计算签名】将双方约定的密钥K1拼接在S2的前部，得到S3;
  4. 【计算签名】计算S3的MD5，并取得Hex字符串的小写形式M1;
  5. 【拼接结果】将M1和S2拼接得到最终密文报文：R

解密步骤：
  1. 【拆解密文】取得密文报文字符串S1的前32个字符，得到签名M1，取得32个字符后的内容，得到S2;
  2. 【验证签名】将双方约定的密钥K1拼接在S2的前部，得到S3;
  3. 【验证签名】计算S3的MD5，并取得Hex字符串的小写形式M2
  4. 【验证签名】判断M1是否等于M2，不相等则验签失败，否则继续如下解密步骤；
  5. 【解密报文】取得S2的反Base64后的密文字节数组B1;
  6. 【解密报文】通过双方约定的密钥K1使用DES解密密文字节数组B1，得到明文报文：R
*/

// 加密
func DesMd5Encode(src, key string) (string, error) {
	b1, err := DesCBCEncrypt([]byte(src), []byte(key), []byte(key), PKCS5_PADDING)
	if err != nil {
		return "", err
	}
	s2 := base64.StdEncoding.EncodeToString(b1)
	s3 := key + s2
	m1 := Md5(s3)
	r := m1 + s2
	return r, nil
}

// 解密
func DesMd5Decode(src, key string) (string, error) {
	m1 := src[0:32]
	s2 := src[32:]
	s3 := key + s2
	m2 := Md5(s3)
	if m1 != m2 {
		return "", errors.New("SignError")
	}
	b1, err := base64.StdEncoding.DecodeString(s2)
	if err != nil {
		return "", err
	}
	bytes, err := DesCBCDecrypt(b1, []byte(key), []byte(key), PKCS5_PADDING)
	if err != nil {
		return "", err
	}
	r := string(bytes)
	return r, nil
}
