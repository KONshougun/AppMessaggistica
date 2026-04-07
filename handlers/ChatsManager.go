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
		cipherName, err = crypto.EncodeChaCha20Poly1305(chatKey[:], chatNonce[:], []byte(name))
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

func newMember(tx *sql.Tx, chatId uint64, chatKey [32]byte, idUser uint64, userMk []byte, withSymCrypto bool) bool {
	if withSymCrypto {

		//	CHAT_KEY
		chatKeyNonce, err := dbData.NewUserNonce(tx, idUser)
		if err != nil {
			return false
		}
		cipherChatKey, err := crypto.EncodeChaCha20Poly1305(userMk, chatKeyNonce, chatKey[:])
		if err != nil {
			return false
		}

		query := fmt.Sprintf(`
			INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
			VALUES (?,?,?,?,?,?);`,
			dbData.MembersChat, dbData.IdUser, dbData.IdChat, dbData.ChatKey, dbData.ChatKeyNonce)
		_, err = tx.Exec(query, idUser, chatId, cipherChatKey, chatKeyNonce)
		if err != nil {
			return false
		}

	} else {
		query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", dbData.PubKey, dbData.Users, dbData.Id)
		err := tx.QueryRow(query, idUser).Scan(&publicKey)

		cipherChatKey, err := crypto.EncodeECIES256(publicKey[:], chatKey[:])
		if err != nil {
			return false
		}

		query = fmt.Sprintf(`
			INSERT INTO %s (%s, %s, %s, %s, %s) 
			VALUES (?,?,?,?,?);`, dbData.MembersChat, dbData.IdUser, dbData.IdChat, dbData.ChatKey, dbData.KeyFlag)
		_, err = tx.Exec(query, idUser, chatId, cipherChatKey, 1)
		if err != nil {
			return false
		}
	}
	return true
}
