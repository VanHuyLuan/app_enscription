// utils.go
package main

import (
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func generatePrime(bits int) string {
	prime, _ := secp256k1.S256().N.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	return prime.String()
}
