package handlers

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"sync"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/dbData"
)

// PER CREATE_CHAT
var mu sync.Mutex

// chatId
// chatKey
func newChat(tx *sql.Tx, name string) (uint64, [32]byte) {
	mu.Lock()
	defer mu.Unlock()
	chatKey, err := newChatKey()
	if err != nil {
		return 0, [32]byte{}
	}

	//	------------------------	PRIMA DEVO CONTROLLARE SE LA CHAT GIA ESISTE

	// CREO LA CHAT
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (?);", dbData.Chats, dbData.Name)
	_, err = tx.Exec(query, "")
	if err != nil {
		return 0, [32]byte{}
	}

	var chatId uint64
	err = tx.QueryRow(fmt.Sprintf("SELECT MAX(%v) FROM %s", dbData.Id, dbData.Chats)).Scan(&chatId)
	if err != nil {
		return 0, [32]byte{}
	}

	var cipherName []byte = nil
	if name != "" {
		var chatNonce [24]byte
		cipherName, err = crypto.EncryptXChaCha20Poly1305(chatKey[:], chatNonce[:], []byte(name))
		if err != nil {
			return 0, [32]byte{}
		}

		query = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?;", dbData.Chats, dbData.Name, dbData.Id)
		_, err := tx.Exec(query, cipherName, chatId)
		if err != nil {
			return 0, [32]byte{}
		}
	}
	return chatId, chatKey
}

func newChatKey() ([32]byte, error) {
	var key [32]byte

	_, err := rand.Read(key[:])
	if err != nil {
		return [32]byte{}, err
	}
	return key, nil
}

func newMember(tx *sql.Tx, chatId uint64, chatKey [32]byte, idUser uint64, userKey []byte) bool {
	if userKey == nil {
		userKey = GetUserKey(tx, idUser)
		if userKey == nil {
			return false
		}
	}

	//	CHAT_KEY
	chatKeyNonce := dbData.NewUserNonce(tx, idUser)
	if chatKeyNonce == nil {
		return false
	}
	cipherChatKey, err := crypto.EncryptXChaCha20Poly1305(userKey, chatKeyNonce, chatKey[:])
	if err != nil {
		return false
	}

	query := fmt.Sprintf(`
			INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
			VALUES (?,?,?,?,?,?);
		`,
		dbData.MembersChat, dbData.IdUser, dbData.IdChat, dbData.ChatKey, dbData.ChatKeyNonce)
	if _, err = tx.Exec(query, idUser, chatId, cipherChatKey, chatKeyNonce); err != nil {
		return false
	}
	return true
}
