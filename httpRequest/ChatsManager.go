package httpRequest

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"strconv"

	"github.com/KONshougun/AppMessaggistica/crypto"
)

func getChatKey() ([16]byte, error) {
	var key [16]byte

	_, err := rand.Read(key[:])
	if err != nil {
		return key, err
	}
	return key, nil
}

func getKeyChaCha20FromMembers(id_user uint64, password string) [32]byte {
	var key [32]byte

	copy(key[:8], []byte(password)[:8])
	copy(key[8:16], []byte(password)[:8])
	binary.BigEndian.PutUint64(key[16:24], id_user)
	binary.BigEndian.PutUint64(key[24:32], id_user)
	return key
}

func createChat(db *sql.DB, name string, idMember uint64, passwords ...string) bool {
	var password string = ""

	chatKey, err := getChatKey()
	if err != nil {
		return false
	}
	var lastID uint64
	query := "SELECT COALESCE(MAX(id), 0) from chats"
	err = db.QueryRow(query).Scan(&lastID)
	if err != nil {
		return false
	}
	chatId := lastID + 1

	if len(passwords) != 0 {
		password = passwords[0]

		var cipherName []byte = nil
		if name != "" {
			var chatNonce [16]byte
			binary.BigEndian.PutUint64(chatNonce[0:8], chatId)
			binary.BigEndian.PutUint64(chatNonce[8:16], 0)
			cipherName, err = crypto.EncodeAES128(chatKey[:], chatNonce[:], []byte(name))
			if err != nil {
				return false
			}
		}

		//	CREO LA CHAT
		//	------------------------	PRIMA DEVO CONTROLLARE SE LA CHAT GIA ESISTE
		query = "INSERT INTO chats (name) VALUES (?);"
		_, err = db.Exec(query, cipherName)
		if err != nil {
			return false
		}

	}

	tx, err := db.Begin()
	if err != nil {
		return false
	}
	//	CREO IL MEMBRO DELLA CHAT
	if password != "" {
		memberKey := getKeyChaCha20FromMembers(idMember, password)

		//	ID_CHAT
		var nonce [24]byte
		binary.BigEndian.PutUint64(nonce[0:8], idMember)
		copy(nonce[8:16], []byte(password)[:8])
		binary.BigEndian.PutUint64(nonce[16:24], idMember)
		cipherIdChat, err := crypto.EncodeChaCha20(memberKey, nonce, []byte(strconv.FormatUint(chatId, 10)))
		if err != nil {
			return false
		}

		//	CHAT_KEY
		copy(nonce[16:24], cipherIdChat)
		cipherChatKey, err := crypto.EncodeChaCha20(memberKey, nonce, chatKey[:])
		if err != nil {
			return false
		}

		//	MSG_BEGIN
		copy(nonce[8:24], cipherChatKey)
		cipherMsgBegin, err := crypto.EncodeChaCha20(memberKey, nonce, []byte{0})
		if err != nil {
			return false
		}

		query = "INSERT INTO members_chat (id_user, id_chat, id_msg_begin, chat_key) VALUES (?,?,?,?);"
		_, err = tx.Exec(query, idMember, cipherIdChat, cipherMsgBegin, cipherChatKey)
		if err != nil {
			tx.Rollback()
			return false
		}

	} else {
		var publicKey []byte
		query = "SELECT public_key FROM users WHERE id = ?"
		err := db.QueryRow(query, idMember).Scan(&publicKey)
		if len(publicKey) != 33 {
			return false
		}

		cipherIdChat, err := crypto.EncodeECIES256(publicKey[:], []byte(strconv.FormatUint(chatId, 10)))
		if err != nil {
			return false
		}
		cipherMsgBegin, err := crypto.EncodeECIES256(publicKey[:], []byte{0})
		if err != nil {
			return false
		}
		cipherChatKey, err := crypto.EncodeECIES256(publicKey[:], chatKey[:])
		if err != nil {
			return false
		}

		query = "INSERT INTO members_chat (id_user, id_chat, id_msg_begin, chat_key, key_flag) VALUES (?,?,?,?,?);"
		_, err = tx.Exec(query, idMember, cipherIdChat, cipherMsgBegin, cipherChatKey, 1)
		if err != nil {
			tx.Rollback()
			return false
		}
	}

	err = tx.Commit()
	return err == nil
}
