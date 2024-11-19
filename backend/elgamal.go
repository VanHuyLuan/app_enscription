// elgamal.go
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

var p, g, x, y *big.Int

// Tạo khóa ElGamal
func generateElGamalKeys(bits int) {
	p = new(big.Int)
	g = new(big.Int)
	x = new(big.Int)
	y = new(big.Int)

	p.SetString(generatePrime(bits), 10)
	g.SetInt64(2)
	x, _ = rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
	x.Add(x, big.NewInt(1))
	y.Exp(g, x, p)
}

// Mã hóa ElGamal
func encryptElGamal(message string) (string, error) {
	msgInt := new(big.Int).SetBytes([]byte(message))
	if msgInt.Cmp(p) >= 0 {
		return "", fmt.Errorf("message quá lớn")
	}

	k, _ := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
	k.Add(k, big.NewInt(1))
	c1 := new(big.Int).Exp(g, k, p)
	s := new(big.Int).Exp(y, k, p)
	c2 := new(big.Int).Mul(msgInt, s)
	c2.Mod(c2, p)

	return fmt.Sprintf("%x,%x", c1, c2), nil
}

// Giải mã ElGamal
func decryptElGamal(encryptedMessage string) (string, error) {
	parts := strings.Split(encryptedMessage, ",")
	if len(parts) != 2 {
		return "", fmt.Errorf("sai định dạng bản mã")
	}

	c1, _ := new(big.Int).SetString(parts[0], 16)
	c2, _ := new(big.Int).SetString(parts[1], 16)

	s := new(big.Int).Exp(c1, x, p)
	sInv := new(big.Int).ModInverse(s, p)

	msgInt := new(big.Int).Mul(c2, sInv)
	msgInt.Mod(msgInt, p)

	return string(msgInt.Bytes()), nil
}

// Tạo chữ ký ElGamal
func signElGamal(message string) (string, error) {
	msgInt := new(big.Int).SetBytes([]byte(message))

	// Chọn k ngẫu nhiên
	k, _ := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
	k.Add(k, big.NewInt(1))

	// Tính r = g^k mod p
	r := new(big.Int).Exp(g, k, p)

	// Tính s = k^-1 * (H(m) - x * r) mod (p - 1)
	h := new(big.Int).Set(msgInt)
	s := new(big.Int).Sub(h, new(big.Int).Mul(x, r))
	s.Mod(s, new(big.Int).Sub(p, big.NewInt(1)))
	sInv := new(big.Int).ModInverse(k, new(big.Int).Sub(p, big.NewInt(1)))
	s.Mul(s, sInv)
	s.Mod(s, new(big.Int).Sub(p, big.NewInt(1)))

	// Trả về chữ ký (r, s)
	return fmt.Sprintf("%x,%x", r, s), nil
}

// Xác minh chữ ký ElGamal
func verifyElGamal(message string, signature string) (bool, error) {
	// Chia tách chữ ký thành (r, s)
	parts := strings.Split(signature, ",")
	if len(parts) != 2 {
		return false, fmt.Errorf("sai định dạng chữ ký")
	}

	r, _ := new(big.Int).SetString(parts[0], 16)
	s, _ := new(big.Int).SetString(parts[1], 16)

	// Tính H(m)
	msgInt := new(big.Int).SetBytes([]byte(message))

	// Tính v1 = g^H(m) * y^r mod p
	v1 := new(big.Int).Exp(g, msgInt, p)
	v2 := new(big.Int).Mul(new(big.Int).Exp(y, r, p), new(big.Int).Exp(r, s, p))
	v2.Mod(v2, p)

	// Kiểm tra v1 == v2
	return v1.Cmp(v2) == 0, nil
}

// func main() {
// 	// Tạo khóa ElGamal
// 	generateElGamalKeys(512)

// 	// Mã hóa thông điệp
// 	message := "Hello, ElGamal!"
// 	fmt.Println("Original message:", message)

// 	// Mã hóa thông điệp
// 	encryptedMessage, err := encryptElGamal(message)
// 	if err != nil {
// 		fmt.Println("Error encrypting message:", err)
// 		return
// 	}
// 	fmt.Println("Encrypted message:", encryptedMessage)

// 	// Giải mã thông điệp
// 	decryptedMessage, err := decryptElGamal(encryptedMessage)
// 	if err != nil {
// 		fmt.Println("Error decrypting message:", err)
// 		return
// 	}
// 	fmt.Println("Decrypted message:", decryptedMessage)

// 	// Tạo chữ ký
// 	signature, err := signElGamal(message)
// 	if err != nil {
// 		fmt.Println("Error signing message:", err)
// 		return
// 	}
// 	fmt.Println("Signature:", signature)

// 	// Xác minh chữ ký
// 	valid, err := verifyElGamal(message, signature)
// 	if err != nil {
// 		fmt.Println("Error verifying signature:", err)
// 		return
// 	}
// 	fmt.Println("Signature valid:", valid)
// }
