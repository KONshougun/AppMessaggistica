package httpRequest

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/dbData"
)

func SendMessage(w http.ResponseWriter, r *http.Request) {
	fmt.Println("SendMessage")

	db, err := InitConnections(w, r)
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}
	defer db.Close()

	id, err := strconv.ParseUint(r.PostForm.Get(Id), 10, 64)
	if err != nil {
		fmt.Fprintf(w, `{"%s": id non valido}`, Error)
		return
	}
	var password string = r.PostForm.Get(Password)
	chatId, err := strconv.ParseUint(r.PostForm.Get(ChatId), 10, 64)
	if err != nil {
		fmt.Fprintf(w, `{"%s": id chat non valido}`, Error)
		return
	}
	var message string = r.PostForm.Get(Message)
	sendTime := time.Now()

	key := AuthenticateUser(id, password, db)
	if key == nil {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	//	CERCA LA CHAT_KEY
	idChatHash, err := crypto.EncodeHmacSha256(strconv.FormatUint(chatId, 10))
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Errore nella verifica dell'appartenenza alla chat"}`, Error)
		return
	}

	var cipherChatKey []byte
	var chatKeyNonce []byte
	query := fmt.Sprintf(`
		SELECT %s, %s FROM %s WHERE %s = ? AND %s = ?;`,
		dbData.ChatKey, dbData.ChatKeyNonce, dbData.MembersChat, dbData.IdUser, dbData.IdChatHash)
	err = db.QueryRow(query, id, idChatHash).Scan(&cipherChatKey, &chatKeyNonce)
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Non sei nella chat richiesta"}`, Error)
		return
	}
	chatKey, err := crypto.DecodeChaCha20(key, chatKeyNonce, cipherChatKey)
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Errore nella verifica dell'appartenenza alla chat"}`, Error)
		return
	}

	var lastID uint64
	query = fmt.Sprintf("SELECT COALESCE(MAX(%s), 0) FROM %s WHERE %s = ?", dbData.Id, dbData.Messages, dbData.IdChat)
	err = db.QueryRow(query, chatId).Scan(&lastID)
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Errore nell'ottenimento dell'id del messaggio"}`, Error)
		return
	}
	msgId := lastID + 1

	//	CIFRO IL MESSAGGIO
	var messageNonce [16]byte
	binary.BigEndian.PutUint64(messageNonce[0:8], chatId)
	binary.BigEndian.PutUint64(messageNonce[8:16], id)
	cipherMsg, err := crypto.EncodeAES(chatKey, messageNonce[:], []byte(message))
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Errore nella crittografia del messaggio"}`, Error)
		return
	}
	//CIFRO IL SEND TIME
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(sendTime.Unix()))
	binary.BigEndian.PutUint64(messageNonce[0:8], 0)
	cipherTime, err := crypto.EncodeAES(chatKey, messageNonce[:], timeBytes)
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Errore nella crittografia del tempo di invio"}`, Error)
		return
	}

	//	INSERISCO IL MESSAGGIO NEL DB
	query = fmt.Sprintf(`
		INSERT INTO %s(%s, %s, %s, %s, %s) 
		VALUES(?,?,?,?,?)`,
		dbData.Messages, dbData.Id, dbData.IdChat, dbData.IdSender, dbData.Message, dbData.SendTime)

	_, err = db.Exec(query, msgId, chatId, id, cipherMsg, cipherTime)
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v`, Error, err)
	} else {
		fmt.Fprintf(w, `{"%s":%v}`, Success, true)
	}

}
