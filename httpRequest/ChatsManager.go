package httpRequest

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"strconv"
	"sync"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/dbData"
)

// PER CREATE_CHAT
var mu sync.Mutex



//chatId
//chatKey
func newChat(tx *sql.Tx, name string) (uint64, [16]byte) {
	mu.Lock()
	defer mu.Unlock()
	chatKey, err := newChatKey()
	if err != nil {
		return 0, [16]byte{}
	}

	//	------------------------	PRIMA DEVO CONTROLLARE SE LA CHAT GIA ESISTE
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (?);", dbData.Chats, dbData.Name)
	_, err = tx.Exec(query, "")
	if err != nil {
		return 0, [16]byte{}
	}

	var chatId uint64
	err = tx.QueryRow(fmt.Sprintf("SELECT MAX(%v) FROM %s", dbData.Id, dbData.Chats)).Scan(&chatId)
	if err != nil {
		return 0, [16]byte{}
	}

	var cipherName []byte = nil
	if name != "" {
		var chatNonce [16]byte
		cipherName, err = crypto.EncodeAES(chatKey[:], chatNonce[:], []byte(name))
		if err != nil {
			return 0, [16]byte{}
		}

		query = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?;", dbData.Chats, dbData.Name, dbData.Id)
		_, err := tx.Exec(query, cipherName, chatId)
		if err != nil {
			return 0, [16]byte{}
		}
	}
	return chatId, chatKey
}

func newChatKey() ([16]byte, error) {
	var key [16]byte

	_, err := rand.Read(key[:])
	if err != nil {
		return key, err
	}
	return key, nil
}

func newMember(tx *sql.Tx, chatId uint64, chatKey [16]byte, idUser uint64, userMk []byte, password string) bool {
	idChatHash, err := crypto.EncodeHmacSha256(strconv.FormatUint(chatId, 10))
	if err != nil {
		return false
	}
	if password != "" {

		//	ID_CHAT
		idChatNonce, err := dbData.NewNonce(tx, idUser)
		if err != nil {
			return false
		}

		cipherIdChat, err := crypto.EncodeChaCha20(userMk, idChatNonce, []byte(strconv.FormatUint(chatId, 10)))
		if err != nil {
			return false
		}

		//	CHAT_KEY
		chatKeyNonce, err := dbData.NewNonce(tx, idUser)
		if err != nil {
			return false
		}
		cipherChatKey, err := crypto.EncodeChaCha20(userMk, chatKeyNonce, chatKey[:])
		if err != nil {
			return false
		}

		query := fmt.Sprintf(`
			INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
			VALUES (?,?,?,?,?,?);`,
			dbData.MembersChat, dbData.IdUser, dbData.IdChatHash, dbData.IdChat, dbData.IdChatNonce, dbData.ChatKey, dbData.ChatKeyNonce)
		_, err = tx.Exec(query, idUser, idChatHash, cipherIdChat, idChatNonce, cipherChatKey, chatKeyNonce)
		if err != nil {
			return false
		}

	} else {
		var publicKey []byte
		query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", dbData.PubKey, dbData.Users, dbData.Id)
		err := tx.QueryRow(query, idUser).Scan(&publicKey)

		cipherIdChat, err := crypto.EncodeECIES256(publicKey[:], []byte(strconv.FormatUint(chatId, 10)))
		if err != nil {
			return false
		}
		cipherChatKey, err := crypto.EncodeECIES256(publicKey[:], chatKey[:])
		if err != nil {
			return false
		}

		query = fmt.Sprintf(`
			INSERT INTO %s (%s, %s, %s, %s, %s) 
			VALUES (?,?,?,?,?);`, dbData.MembersChat, dbData.IdUser, dbData.IdChatHash, dbData.IdChat, dbData.ChatKey, dbData.KeyFlag)
		_, err = tx.Exec(query, idUser, idChatHash, cipherIdChat, cipherChatKey, 1)
		if err != nil {
			return false
		}
	}
	return true
}
