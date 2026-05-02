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
func newChat(tx *sql.Tx, name string) (int64, [32]byte, error) {
	mu.Lock()
	defer mu.Unlock()
	chatKey, err := newChatKey()
	if err != nil {
		return -1, [32]byte{}, err
	}

	//	------------------------	PRIMA DEVO CONTROLLARE SE LA CHAT GIA ESISTE

	// CREO LA CHAT
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (?);", dbData.Chats, dbData.Name)
	response, err := tx.Exec(query, name)
	if err != nil {
		return -1, [32]byte{}, err
	}
	chatId, err := response.LastInsertId()
	if err != nil {
		return -1, [32]byte{}, err
	}
	return chatId, chatKey, nil
}

func newChatKey() ([32]byte, error) {
	var key [32]byte

	_, err := rand.Read(key[:])
	if err != nil {
		return [32]byte{}, err
	}
	return key, nil
}

func newMember(tx *sql.Tx, chatId int64, chatKey [32]byte, idUser int64, key []byte) bool {
	fmt.Println("ciao")
	if len(key) == 32 {

		//	CHAT_KEY
		chatKeyNonce := dbData.NewUserNonce(tx, idUser)
		if chatKeyNonce == nil {
			return false
		}
		cipherChatKey, err := crypto.EncryptXChaCha20Poly1305(key, chatKeyNonce, chatKey[:])
		if err != nil {
			return false
		}

		query := fmt.Sprintf(`
			INSERT INTO %s (%s, %s, %s, %s) 
			VALUES (?,?,?,?);`,
			dbData.MembersChat, dbData.IdUser, dbData.IdChat, dbData.ChatKey, dbData.ChatKeyNonce)
		_, err = tx.Exec(query, idUser, chatId, cipherChatKey, chatKeyNonce)
		if err != nil {
			return false
		}

	} else {
		query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", dbData.PubKey, dbData.Users, dbData.Id)
		err := tx.QueryRow(query, idUser).Scan(&key)

		cipherChatKey, err := crypto.EncodeECIES256(key[:], chatKey[:])
		if err != nil {
			return false
		}

		query = fmt.Sprintf(`
			INSERT INTO %s (%s, %s, %s, %s) 
			VALUES (?,?,?,?);`, dbData.MembersChat, dbData.IdUser, dbData.IdChat, dbData.ChatKey, dbData.Flag)
		_, err = tx.Exec(query, idUser, chatId, cipherChatKey, 1)
		if err != nil {
			return false
		}
	}
	fmt.Println("successo")
	return true
}
