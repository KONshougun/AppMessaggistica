package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/dbData"
)

// PER CREATE_CHAT
var mu sync.Mutex

type Chat struct {
	IdChat   int64
	NameChat string
	Members  []MemberChat
	Messages []Message
	IdMsgBgn int64
}

type Message struct {
	Sender   string
	Message  string
	SendTime time.Time
}

type MemberChat struct {
	Username    string
	LastMsgRead int64
}

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

func GetChats(conn *Conn, id int64, userKey []byte) {
	fmt.Println("GetChats")

	db, err := dbData.StartConnection()
	if err != nil {
		fmt.Println(err.Error())
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
	defer db.Close()

	if err = SendPacket(conn, LOAD_START, false, nil); err != nil {
		fmt.Println(err.Error())
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	query := fmt.Sprintf(`
		SELECT %s, %s,%s,  %s, %s
		FROM %s
		INNER JOIN %s ON %s = %s
		WHERE %s = ?`,
		dbData.Id, dbData.Name, dbData.IdMsgBgn, dbData.ChatKey, dbData.ChatKeyNonce,
		dbData.MembersChat, dbData.Chats, dbData.Id, dbData.IdChat, dbData.IdUser)

	chatsRows, err := db.Query(query, id)
	if err != nil {
		fmt.Println("Ciao")
		fmt.Println(err.Error())
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	var chats []Chat
	for chatsRows.Next() {

		var idChat, idMsgBgn int64
		var nameChat string
		var cipherChatKey, chatKeyNonce []byte

		if err = chatsRows.Scan(&idChat, &nameChat, &idMsgBgn, &cipherChatKey, &chatKeyNonce); err != nil {
			fmt.Println(err.Error())
			fmt.Println("sono")
			SendPacket(conn, ERROR, false, []byte(err.Error()))
			return
		}
		chats = append(chats, Chat{
			IdChat:   idChat,
			NameChat: nameChat,
			IdMsgBgn: idMsgBgn,
		})

		chatKey, err := crypto.DecryptXChaCha20Poly1305(userKey, chatKeyNonce, cipherChatKey)
		if err != nil {
			fmt.Println(err.Error())
			fmt.Println("giu")
			SendPacket(conn, ERROR, false, []byte(err.Error()))
			return
		}
		query = fmt.Sprintf(`
			SELECT %s, %s, %s, %s
			FROM %s msgs
			INNER JOIN %s u ON %s = u.%s
			WHERE %s = ? AND msgs.%s > ?`,
			dbData.Username, dbData.Message, dbData.MessageNonce, dbData.SendTime,
			dbData.Messages, dbData.Users, dbData.IdSender, dbData.Id,
			dbData.IdChat, dbData.Id)

		messagesRows, err := db.Query(query, idChat, idMsgBgn)
		if err != nil {
			fmt.Println("sep")
			fmt.Println(err.Error())
			SendPacket(conn, ERROR, false, []byte(err.Error()))
			return
		}

		for messagesRows.Next() {
			var sender string
			var cipherMsg, messageNonce []byte
			var sendTime time.Time
			if err = messagesRows.Scan(&sender, &cipherMsg, &messageNonce, &sendTime); err != nil {
				fmt.Println(err.Error())
				fmt.Println("pe")
				SendPacket(conn, ERROR, false, []byte(err.Error()))
				return
			}
			message, err := crypto.DecryptXChaCha20Poly1305(chatKey, messageNonce, cipherMsg)
			if err != nil {
				fmt.Println("dove")
				fmt.Println(err.Error())
				SendPacket(conn, ERROR, false, []byte(err.Error()))
				return
			}
			chats[len(chats)-1].Messages = append(chats[len(chats)-1].Messages, Message{
				Sender:   sender,
				Message:  string(message),
				SendTime: sendTime,
			})

		}
		messagesRows.Close()

		query = fmt.Sprintf(`
			SELECT %s, %s
			FROM %s
			INNER JOIN %s ON %s = %s
			WHERE %s != ? AND
				%s IN(
					SELECT %s
					FROM %s
					WHERE %s = ?
				)`,
			dbData.Username, dbData.LastMsgReadId,
			dbData.MembersChat, dbData.Users, dbData.Id, dbData.IdUser,
			dbData.IdUser, dbData.IdChat,
			dbData.IdChat, dbData.MembersChat, dbData.IdUser)

		membersRows, err := db.Query(query, id, id)
		if err != nil {
			fmt.Println("è arriv")
			fmt.Println(err.Error())
			SendPacket(conn, ERROR, false, []byte(err.Error()))
			return
		}
		for membersRows.Next() {
			var memberUsername string
			var lastMsgRead int64
			if err = membersRows.Scan(&memberUsername, &lastMsgRead); err != nil {
				fmt.Println(err.Error())
				fmt.Println("ato")
				SendPacket(conn, ERROR, false, []byte(err.Error()))
				return
			}
			chats[len(chats)-1].Members = append(chats[len(chats)-1].Members, MemberChat{
				Username:    memberUsername,
				LastMsgRead: lastMsgRead,
			})
		}
		messagesRows.Close()
	}
	chatsRows.Close()

	var buffer []Chat

	for _, chat := range chats {
		buffer = append(buffer, chat)

		data, err := json.Marshal(buffer)
		if err != nil {
			fmt.Println("il")
			fmt.Println(err.Error())
			SendPacket(conn, ERROR, false, []byte(err.Error()))
			return
		}

		if len(data) > 5000 {
			last := buffer[len(buffer)-1]

			toSend := buffer[:len(buffer)-1]

			payload, _ := json.Marshal(toSend)
			SendPacket(conn, PROGRESS, true, payload)

			// reset batch con ultimo elemento
			buffer = []Chat{last}
		}
	}
	if len(buffer) > 0 {
		payload, _ := json.Marshal(buffer)
		SendPacket(conn, PROGRESS, true, []byte(payload))
	}

	if err = SendPacket(conn, LOAD_END, false, nil); err != nil {
		fmt.Printf("err: %v\n", err)
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

}
