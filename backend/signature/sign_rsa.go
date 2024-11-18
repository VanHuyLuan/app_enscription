package main

import (
	"errors"
	"math/big"
	"strings"
)

// Hàm Hashing
func hashing(txt string) *big.Int {
	txt = strings.ToUpper(txt)
	ans := big.NewInt(0)
	base := big.NewInt(26)
	for _, c := range txt {
		val := big.NewInt(int64(c - 'A'))
		ans.Mul(ans, base).Add(ans, val)
	}
	return ans
}

// Mã hóa mô-đun
func modularExponential(a, b, n *big.Int) *big.Int {
	result := big.NewInt(1)
	base := new(big.Int).Mod(a, n)
	exp := new(big.Int).Set(b)

	for exp.Sign() > 0 {
		if exp.Bit(0) == 1 {
			result.Mod(result.Mul(result, base), n)
		}
		base.Mod(base.Mul(base, base), n)
		exp.Rsh(exp, 1)
	}
	return result
}

// Thuật toán Euclide mở rộng
func extendedGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if b.Sign() == 0 {
		return a, big.NewInt(1), big.NewInt(0)
	}
	gcd, x1, y1 := extendedGCD(b, new(big.Int).Mod(a, b))
	x := new(big.Int).Set(y1)
	y := new(big.Int).Sub(x1, new(big.Int).Mul(a.Div(a, b), y1))
	return gcd, x, y
}

// RSA struct
type RSA struct {
	P, Q, N, Phi, E, D *big.Int
}

// Hàm tạo khóa riêng
func (rsa *RSA) generatePrivateKey() error {
	gcd, x, _ := extendedGCD(rsa.E, rsa.Phi)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return errors.New("e and φ(n) are not coprime")
	}
	rsa.D = new(big.Int).Mod(x, rsa.Phi)
	return nil
}

// Hàm ký số
func (rsa *RSA) Sign(message string) *big.Int {
	hashed := hashing(message)
	return modularExponential(hashed, rsa.D, rsa.N)
}

// Hàm xác thực chữ ký
func (rsa *RSA) Verify(signature *big.Int, message string) bool {

	hashedMessage := hashing(message)

	decryptedHash := modularExponential(signature, rsa.E, rsa.N)
	return decryptedHash.Cmp(hashedMessage) == 0
}
