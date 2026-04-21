package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func GenerateKyberKey() (kem.PublicKey, kem.PrivateKey, error) {
	scheme := kyber768.Scheme()
	pub, priv, err := scheme.GenerateKeyPair()
	return pub, priv, err
}

// ciphertext AES, nonce, encapsulated key (ctKEM)
func EncryptKyber(pub kem.PublicKey, plaintext []byte) (ciphertext, nonce, ctKEM []byte, err error) {

	scheme := kyber768.Scheme()

	ctKEM, shared, err := scheme.Encapsulate(pub)
	if err != nil {
		return nil, nil, nil, err
	}

	key := sha256.Sum256(shared)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, ctKEM, nil
}

func DecryptKyber(priv kem.PrivateKey, ciphertext, nonce, ctKEM []byte) ([]byte, error) {

	scheme := kyber768.Scheme()

	shared, err := scheme.Decapsulate(priv, ctKEM)
	if err != nil {
		return nil, err
	}

	key := sha256.Sum256(shared)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}
