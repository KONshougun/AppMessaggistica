package handlers

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/KONshougun/AppMessaggistica/crypto"
)

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
	if err != nil || len(nonce) != 8 {
		return nil
	}
	return nonce
}

// Cripta la MK
func EncryptMK(clientId uint64, clientNonce []byte, plaintext []byte) []byte {
	key := getEnvKey()
	if len(key) != 32{
		fmt.Println("Chiave")
		return nil
	}
	serverNonce := getEnvNonce()
	if len(serverNonce) != 8 {
		fmt.Println("nonce")
		return nil
	}

	nonce := make([]byte, 24)
	copy(nonce[:8], serverNonce)
	binary.LittleEndian.PutUint64(nonce[8:16], clientId)
	copy(nonce[16:], clientNonce)

	cipherText, err := crypto.EncodeChaCha20Poly1305(key, nonce, plaintext)
	if err != nil {
		fmt.Println("crypto")
		return nil
	}
	return cipherText
}

func DecryptMK(nonce []byte, ciphertext []byte) []byte {
	key := getEnvKey()
	if key == nil {
		return nil
	}

	plaintext, err := crypto.DecodeChaCha20Poly1305(key, nonce, ciphertext)
	if err != nil {
		return nil
	}
	return plaintext
}
