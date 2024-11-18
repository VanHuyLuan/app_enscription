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
