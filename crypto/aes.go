package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// key 	= 16B
// nonce 	= 16B
func EncodeAES128(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {

	if len(key) != 16 || len(nonce) != 16 {
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

func DecodeAES128(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != 16 || len(nonce) != 16 {
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
