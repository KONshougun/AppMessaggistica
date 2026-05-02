package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
)

func EncodeHmacSha256(arg string) ([]byte, error) {

	keyHex := os.Getenv("SERVER_SHA_KEY")
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
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
