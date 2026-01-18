package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"log"
	"os"
)

func EncodeHmacSha256(arg string) ([]byte, error) {
	key := []byte(os.Getenv("SERVER_KEY"))
	if len(key) == 0 {
		return nil, log.Output(1, "SERVER_KEY non impostata")
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(arg))
	hash := h.Sum(nil)
	return hash, nil
}

/*
func VerifyHmacSha256(arg string, hash []byte) bool {
	key := []byte(os.Getenv("SERVER_KEY"))
	if len(key) == 0 {
		log.Output(1, "SERVER_KEY non impostata")
		return false
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(arg))
	expectedMac := h.Sum(nil)
	return hmac.Equal(hash, expectedMac)
}
*/
