package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// Chia thông điệp thành các khối nhỏ
func splitRSAMessage(message []byte, blockSize int) [][]byte {
	var blocks [][]byte
	for len(message) > 0 {
		if len(message) > blockSize {
			blocks = append(blocks, message[:blockSize])
			message = message[blockSize:]
		} else {
			blocks = append(blocks, message)
			break
		}
	}
	return blocks
}

// Mã hóa RSA
func encryptRSA(message string) (string, error) {
	blockSize := rsaPublicKey.Size() - 2*sha256.Size - 2 
	blocks := splitRSAMessage([]byte(message), blockSize)

	var encryptedBlocks []string
	for _, block := range blocks {
		encryptedBytes, err := rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			rsaPublicKey,
			block,
			nil,
		)
		if err != nil {
			return "", err
		}
		encryptedBlocks = append(encryptedBlocks, base64.StdEncoding.EncodeToString(encryptedBytes))
	}

	encryptedMessage, err := json.Marshal(encryptedBlocks)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedMessage), nil
}

// Giải mã RSA
func decryptRSA(encryptedMessage string) (string, error) {
	decodedMessage, _ := base64.StdEncoding.DecodeString(encryptedMessage)

	var encryptedBlocks []string
	err := json.Unmarshal(decodedMessage, &encryptedBlocks)
	if err != nil {
		return "", err
	}

	var decryptedMessage []byte
	for _, block := range encryptedBlocks {
		ciphertext, _ := base64.StdEncoding.DecodeString(block)
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
		decryptedMessage = append(decryptedMessage, decryptedBytes...)
	}

	return string(decryptedMessage), nil
}

// Tạo chữ ký số (Digital Signature)
func signMessage(message string) (string, error) {

	hashed := sha256.Sum256([]byte(message))

	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, 0, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// Xác thực chữ ký số (Verify Digital Signature)
func verifySignature(message string, signature string) bool {

	hashed := sha256.Sum256([]byte(message))

	signatureBytes, _ := base64.StdEncoding.DecodeString(signature)
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
