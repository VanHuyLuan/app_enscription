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

// Tạo chữ ký số (Digital Signature)
func signMessage(message string) (string, error) {
	// Hash thông điệp bằng SHA-256
	hashed := sha256.Sum256([]byte(message))
	// Ký thông điệp đã được hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, 0, hashed[:])
	if err != nil {
		return "", err
	}
	// Mã hóa chữ ký bằng Base64
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Xác thực chữ ký số (Verify Digital Signature)
func verifySignature(message string, signature string) bool {
	// Hash thông điệp bằng SHA-256
	hashed := sha256.Sum256([]byte(message))
	// Giải mã chữ ký từ Base64
	signatureBytes, _ := base64.StdEncoding.DecodeString(signature)
	// Xác thực chữ ký bằng khóa công khai
	err := rsa.VerifyPKCS1v15(rsaPublicKey, 0, hashed[:], signatureBytes)
	return err == nil
}

// func main() {
// 	// Tạo cặp khóa RSA (2048 bits)
// 	generateRSAKeys(2048)

// 	// Thông điệp cần mã hóa
// 	message := "Hello, RSA with Digital Signature!"

// 	// Mã hóa thông điệp
// 	encryptedMessage, err := encryptRSA(message)
// 	if err != nil {
// 		fmt.Println("Error encrypting message:", err)
// 		return
// 	}
// 	fmt.Println("Encrypted Message:", encryptedMessage)

// 	// Giải mã thông điệp
// 	decryptedMessage, err := decryptRSA(encryptedMessage)
// 	if err != nil {
// 		fmt.Println("Error decrypting message:", err)
// 		return
// 	}
// 	fmt.Println("Decrypted Message:", decryptedMessage)

// 	// Ký thông điệp
// 	signature, err := signMessage(message)
// 	if err != nil {
// 		fmt.Println("Error signing message:", err)
// 		return
// 	}
// 	fmt.Println("Digital Signature:", signature)

// 	// Xác thực chữ ký
// 	isValid := verifySignature(message, signature)
// 	fmt.Println("Signature Valid:", isValid)
// }
