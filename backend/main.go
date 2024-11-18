// main.go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type EncryptRequest struct {
	Algorithm string `json:"algorithm"`
	Message   string `json:"message"`
}

type DecryptRequest struct {
	Algorithm       string `json:"algorithm"`
	EncryptedMessage string `json:"encryptedMessage"`
}

type EncryptResponse struct {
	EncryptedMessage string `json:"encryptedMessage"`
}

type DecryptResponse struct {
	DecryptedMessage string `json:"decryptedMessage"`
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	var req EncryptRequest
	json.NewDecoder(r.Body).Decode(&req)

	switch strings.ToUpper(req.Algorithm) {
	case "RSA":
		encryptedMessage, err := encryptRSA(req.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(EncryptResponse{EncryptedMessage: encryptedMessage})

	case "ELGAMAL":
		encryptedMessage, err := encryptElGamal(req.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(EncryptResponse{EncryptedMessage: encryptedMessage})
	case "ECC":
		encryptedMessage, err := encryptECC(req.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(EncryptResponse{EncryptedMessage: encryptedMessage})
	}
	
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	var req DecryptRequest
	json.NewDecoder(r.Body).Decode(&req)

	switch strings.ToUpper(req.Algorithm) {
	case "RSA":
		decryptedMessage, err := decryptRSA(req.EncryptedMessage)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(DecryptResponse{DecryptedMessage: decryptedMessage})

	case "ELGAMAL":
		decryptedMessage, err := decryptElGamal(req.EncryptedMessage)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(DecryptResponse{DecryptedMessage: decryptedMessage})
	case "ECC":
		decryptedMessage, err := decryptECC(req.EncryptedMessage)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(DecryptResponse{DecryptedMessage: decryptedMessage})
	}
	
}

// Middleware xử lý CORS
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*") // Cho phép tất cả các nguồn
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        w.Header().Set("Access-Control-Allow-Credentials", "true")

        // Đáp ứng yêu cầu preflight của CORS
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    }
}

func main() {
	generateRSAKeys(2048)
	generateElGamalKeys(512)
	generateECCKeys()

	http.HandleFunc("/encrypt", corsMiddleware(encryptHandler))
    http.HandleFunc("/decrypt", corsMiddleware(decryptHandler))

	fmt.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
