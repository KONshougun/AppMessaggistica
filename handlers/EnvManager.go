package handlers

import (
	"encoding/base64"
	"os"
)

func getEnvPrivKey() []byte {
	keyB64 := os.Getenv("X25519_PRIVATE_KEY")
	if keyB64 == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil
	}

	return key
}
