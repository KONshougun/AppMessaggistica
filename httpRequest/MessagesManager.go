package httpRequest

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/KONshougun/AppMessaggistica/crypto"
)

func SendMessage(w http.ResponseWriter, r *http.Request) {
	fmt.Println("AddContact")

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

	if !AuthenticateUser(id, password, db) {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	//	CONTROLLO SE L'ID_USER SI TROVA IN QUELLA CHAT
	memberKey := getKeyChaCha20FromMembers(id, password)

	var chatNonce [24]byte
	binary.BigEndian.PutUint64(chatNonce[0:8], id)
	copy(chatNonce[8:16], []byte(password)[:8])
	binary.BigEndian.PutUint64(chatNonce[16:24], id)
	cipherIdChat, err := crypto.EncodeChaCha20(memberKey, chatNonce, []byte(strconv.FormatUint(chatId, 10)))
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Errore nella verifica dell'appartenenza alla chat"}`, Error)
		return
	}

	var cipherChatKey []byte
	query := "SELECT chat_key FROM members_chat WHERE id_user = ? AND id_chat = ?;"
	err = db.QueryRow(query, id, cipherIdChat).Scan(&cipherChatKey)
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Non sei nella chat richiesta"}`, Error)
		return
	}
	copy(chatNonce[16:24], cipherIdChat)
	chatKey, err := crypto.DecodeChaCha20(memberKey, chatNonce, cipherChatKey)
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Errore nella verifica dell'appartenenza alla chat"}`, Error)
		return
	}

	var lastID uint64
	query = "SELECT COALESCE(MAX(id), 0) FROM messages WHERE id_chat = ?"
	err = db.QueryRow(query, cipherIdChat).Scan(&lastID)
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Errore nell'ottenimento dell'id del messaggio"}`, Error)
		return
	}
	msgId := lastID + 1

	//	CIFRO IL MESSAGGIO
	var messageNonce [16]byte
	binary.BigEndian.PutUint64(chatNonce[0:8], id)
	binary.BigEndian.PutUint64(chatNonce[8:16], chatId)
	cipherMsg, err := crypto.EncodeAES128(chatKey, messageNonce[:], []byte(message))
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Errore nella crittografia del messaggio"}`, Error)
		return
	}
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(sendTime.Unix()))
	cipherTime, err := crypto.EncodeAES128(chatKey, make([]byte, 16), timeBytes)
	if err != nil {
		fmt.Fprintf(w, `{"%s":"Errore nella crittografia del tempo di invio"}`, Error)
		return
	}

	//	INSERISCO IL MESSAGGIO NEL DB
	query = "INSERT INTO messages(id, id_chat, id_sender, message, send_time) VALUES(?,?,?,?,?)"

	_, err = db.Exec(query, msgId, cipherIdChat, id, cipherMsg, cipherTime)
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v`, Error, err)
	} else {
		fmt.Fprintf(w, `{"%s":%v}`, Success, true)
	}

}
