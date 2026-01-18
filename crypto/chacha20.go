package crypto

import "golang.org/x/crypto/chacha20"

// KEY 32
// NONCE 24
func EncodeChaCha20(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// KEY 32
// NONCE 24
func DecodeChaCha20(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}
