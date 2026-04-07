package handlers

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/dbData"
)

func SendMessage(conn *Conn, msg string, id uint64, userKey []byte) {
	fmt.Println("SendMessage")

	db, err := dbData.StartConnection()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nella lettura del messaggio"))
		return
	}
	defer db.Close()

	msgParams := strings.Split(string(msg), ";")

	chatId, err := strconv.ParseUint(msgParams[0], 10, 64)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nella lettura dell'id della chat"))
		return
	}
	message := msgParams[1]
	if len(message)>1000{
		SendPacket(conn, ERROR, false, []byte("Errore messaggio troppo lungo"))
		return
	}
	sendTime := time.Now()

	//	CERCA LA CHAT_KEY
	var cipherChatKey []byte
	var chatKeyNonce []byte
	query := fmt.Sprintf(`
		SELECT %s, %s FROM %s WHERE %s = ? AND %s = ?;`,
		dbData.ChatKey, dbData.ChatKeyNonce, dbData.MembersChat, dbData.IdUser, dbData.IdChat)
	err = db.QueryRow(query, id, chatId).Scan(&cipherChatKey, &chatKeyNonce)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore ricerca della chiave della chat nel database"))
		return
	}
	chatKey, err := crypto.DecodeChaCha20Poly1305(userKey, chatKeyNonce, cipherChatKey)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nella verifica dell'appartenenza alla chat"))
		return
	}

	var lastID uint64
	query = fmt.Sprintf("SELECT COALESCE(MAX(%s), 0) FROM %s WHERE %s = ?", dbData.Id, dbData.Messages, dbData.IdChat)
	err = db.QueryRow(query, chatId).Scan(&lastID)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nell'ottenimento dell'id del messaggio"))
		return
	}
	msgId := lastID + 1

	//	CIFRO IL MESSAGGIO
	messageNonce, err := dbData.NewChatNonce(db, chatId)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
	cipherMsg, err := crypto.EncodeChaCha20Poly1305(chatKey, messageNonce[:], []byte(message))
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nella crittografia del messaggio"))
		return
	}
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(sendTime.Unix()))

	//	INSERISCO IL MESSAGGIO NEL DB
	query = fmt.Sprintf(`
		INSERT INTO %s(%s, %s, %s, %s, %s) 
		VALUES(?,?,?,?,?)`,
		dbData.Messages, dbData.Id, dbData.IdChat, dbData.IdSender, dbData.Message, dbData.SendTime)

	_, err = db.Exec(query, msgId, chatId, id, cipherMsg, timeBytes)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
	} else {
		SendPacket(conn, SUCCESS, false, []byte{1})
	}

}
