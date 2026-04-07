package crypto

import (
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
)

// KEY 32
// NONCE 24
func EncodeChaCha20Poly1305(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize ||
	 	len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("Parametri di chacha20poly1305 non validi")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// KEY 32
// NONCE 24
func DecodeChaCha20Poly1305(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize ||
	 	len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("Parametri di chacha20poly1305 non validi")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
