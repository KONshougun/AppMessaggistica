package handlers

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/dbData"
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
	if len(key) != 32 {
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

	cipherText, err := crypto.EncryptXChaCha20Poly1305(key, nonce, plaintext)
	if err != nil {
		fmt.Println("crypto")
		return nil
	}
	return cipherText
}

func GetUserKey(qr dbData.QueryRower, idUser uint64) []byte {

	//	RIPRENDO LA CHIAVE CRIPTATA
	query := fmt.Sprintf(`
		SELECT %s, %s
		FROM %s
		WHERE %s = ?
		);
	`, dbData.RecoveryMk, dbData.MkNonce, dbData.Users, dbData.Id)
	var recoveryKey, nonce []byte
	if err := qr.QueryRow(query, idUser).Scan(&recoveryKey, &nonce); err != nil {
		return nil
	}

	userKey := DecryptMK(nonce, recoveryKey)
	return userKey
}

func DecryptMK(nonce []byte, ciphertext []byte) []byte {
	key := getEnvKey()
	if key == nil {
		return nil
	}

	plaintext, err := crypto.DecryptXChaCha20Poly1305(key, nonce, ciphertext)
	if err != nil {
		return nil
	}
	return plaintext
}

/*func RecoveryKey(id uint64) ([]byte, error) {
	recoveryKey := []byte(os.Getenv("RECOVERY_KEY"))

	if len(recoveryKey) != 32 {
		return nil, fmt.Errorf("recovery key non impostata nel server")
	}

	var recoveryMk []byte
	var nonce []byte
	query := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s = ?", dbData.RecoveryMk, dbData.ChatKeyNonce, dbData.Users, dbData.Id)
	if err := db.QueryRow(query, id).Scan(&recoveryMk, &nonce); err != nil {
		return nil, err
	}
	decipherMk, err := crypto.DecodeXChaCha20Poly1305(recoveryKey, nonce, recoveryMk)
	if err != nil {
		return nil, err
	}
	return decipherMk, nil
}*/
