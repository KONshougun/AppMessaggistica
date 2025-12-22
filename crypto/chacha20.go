package crypto

import "golang.org/x/crypto/chacha20"

func EncodeChaCha20(key [32]byte, nonce [24]byte, plaintext []byte) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// DecodeChaCha20 decifra il ciphertext con la stessa chiave e nonce
func DecodeChaCha20(key [32]byte, nonce [24]byte, ciphertext []byte) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}
