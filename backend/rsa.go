package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

var rsaPrivateKey *rsa.PrivateKey
var rsaPublicKey *rsa.PublicKey

// Hàm tính Ước chung lớn nhất (GCD)
func gcd(a, b *big.Int) *big.Int {
	zero := big.NewInt(0)
	for b.Cmp(zero) > 0 {
		a, b = b, new(big.Int).Mod(a, b)
	}
	return a
}

// Hàm tìm số nghịch đảo của e modulo φ(n)
func modInverse_1(e, phi *big.Int) (*big.Int, error) {
	g, x, _ := extendedGCD(e, phi)
	if g.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("e và φ(n) không coprime, không thể tìm nghịch đảo")
	}
	return x.Mod(x, phi), nil
}

// Hàm Extended Euclidean Algorithm để tính nghịch đảo modular
func extendedGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	zero := big.NewInt(0)
	x0, x1, y0, y1 := big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(1)
	for b.Cmp(zero) > 0 {
		q := new(big.Int).Div(a, b)
		a, b = b, new(big.Int).Mod(a, b)
		x0, x1 = x1, new(big.Int).Sub(x0, new(big.Int).Mul(q, x1))
		y0, y1 = y1, new(big.Int).Sub(y0, new(big.Int).Mul(q, y1))
	}
	return a, x0, y0
}

// Hàm tạo cặp khóa RSA tự động
func generateRSAKeys_1(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Tạo số nguyên tố p và q
	p, err := randPrime(bits / 2)
	if err != nil {
		return nil, nil, fmt.Errorf("không thể tạo p: %v", err)
	}
	q, err := randPrime(bits / 2)
	if err != nil {
		return nil, nil, fmt.Errorf("không thể tạo q: %v", err)
	}

	// Tính n = p * q
	n := new(big.Int).Mul(p, q)

	// Tính φ(n) = (p-1)*(q-1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	// Chọn e sao cho 1 < e < φ(n) và gcd(e, φ(n)) = 1
	e := big.NewInt(65537) // Một số công khai phổ biến
	if gcd(e, phi).Cmp(big.NewInt(1)) != 0 {
		return nil, nil, fmt.Errorf("e và φ(n) không coprime")
	}

	// Tính d là nghịch đảo của e mod φ(n)
	d, err := modInverse_1(e, phi)
	if err != nil {
		return nil, nil, fmt.Errorf("không thể tính d: %v", err)
	}

	// Tạo khóa công khai và khóa riêng
	privateKey := &rsa.PrivateKey{
		D:      d,
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
	}
	publicKey := &privateKey.PublicKey

	return privateKey, publicKey, nil
}

// Hàm tạo một số nguyên tố ngẫu nhiên
func randPrime(bits int) (*big.Int, error) {
	// Sử dụng một hàm sinh số ngẫu nhiên với độ dài bits
	// Giới hạn độ dài của bits sẽ tùy thuộc vào yêu cầu bảo mật
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	min := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))

	for {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("lỗi khi tạo số ngẫu nhiên: %v", err)
		}
		n.Add(n, min) // Đảm bảo số nguyên tố có đủ độ dài bits
		if n.ProbablyPrime(20) { // Kiểm tra xem n có phải là số nguyên tố không
			return n, nil
		}
	}
}

// Tạo cặp khóa RSA
func generateRSAKeys(bits int) {
	var err error
	rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Println("Error generating RSA keys:", err)
		return
	}
	rsaPublicKey = &rsaPrivateKey.PublicKey
	println("rsaPrivateKey: ", rsaPrivateKey)
	println( "rsaPublicKey: ",rsaPublicKey)
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
	if rsaPublicKey == nil {
        return "nil", fmt.Errorf("public key is nil")
    }
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
