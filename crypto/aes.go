package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
)

// key 	= 16B
// nonce 	= 16B
func EncodeAES(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {

	if (len(key) != 16 && len(key) != 32) || len(nonce) != 16 {
		return nil, fmt.Errorf("key and nonce must be 16 bytes long")
	}

	// Creazione del blocco AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Creazione del cifrario CTR
	stream := cipher.NewCTR(block, nonce)

	// Cifratura
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

func DecodeAES(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	if (len(key) != 16 && len(key) != 32) || len(nonce) != 16 {
		return nil, fmt.Errorf("key and nonce must be 16 bytes long")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, nonce)
	decrypted := make([]byte, len(ciphertext))
	stream.XORKeyStream(decrypted, ciphertext)

	return decrypted, nil
}

func getEnvKey() []byte {
	keyHex := os.Getenv("RECOVERY_KEY")
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil
	}
	return key
}
func getEnvNonce() []byte {
	nonceHex := os.Getenv("RECOVERY_NONCE")
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != 4 {
		return nil
	}
	return nonce
}

// Cripta la MK
func EncryptMK(clientNonce []byte, plaintext []byte) []byte {
	key := getEnvKey()
	if key == nil {
		return nil
	}
	serverNonce := getEnvNonce()
	if serverNonce == nil {
		return nil
	}

	nonce := make([]byte, 16)
	copy(nonce[:12], clientNonce)
	copy(nonce[12:], serverNonce)

	cipherText, err := EncodeAES(key, nonce, plaintext)
	if err != nil {
		return nil
	}
	return cipherText
}

func DecryptMK(nonce []byte, ciphertext []byte) []byte {
	key := getEnvKey()
	if key == nil {
		return nil
	}

	plaintext, err := DecodeAES(key, nonce, ciphertext)
	if err != nil {
		return nil
	}
	return plaintext
}
