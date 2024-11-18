// rsa.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

var rsaPrivateKey *rsa.PrivateKey
var rsaPublicKey *rsa.PublicKey

// Tạo cặp khóa RSA
func generateRSAKeys(bits int) {
	var err error
	rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Println("Error generating RSA keys:", err)
		return
	}
	rsaPublicKey = &rsaPrivateKey.PublicKey
}

// Mã hóa RSA
func encryptRSA(message string) (string, error) {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaPublicKey,
		[]byte(message),
		nil,
	)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

// Giải mã RSA
func decryptRSA(encryptedMessage string) (string, error) {
	ciphertext, _ := base64.StdEncoding.DecodeString(encryptedMessage)
	decryptedBytes, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaPrivateKey,
		ciphertext,
		nil,
	)
	if err != nil {
		return "", err
	}
	return string(decryptedBytes), nil
}
