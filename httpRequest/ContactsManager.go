package httpRequest

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"

	"github.com/KONshougun/AppMessaggistica/crypto"
)

type Contact struct {
	username  string
	nickname  string
	isBlocked bool
}

// DA MIGLIORARE
func getKeyChaCha20FromContact(id_user uint64, password string) [32]byte {
	var key [32]byte

	binary.BigEndian.PutUint64(key[:8], id_user)
	for i := 1; i <= 3; i++ {
		copy(key[i*8:(i+1)*8], []byte(password)[:8])
	}
	return key
}

// DA MIGLIORARE
func getNicknameNonceChaCha20FromContact(id_user uint64, password string, contactUsername []byte) [24]byte {
	var nonce [24]byte

	var usernameBuff [8]byte
	copy(usernameBuff[:], []byte(contactUsername)[:])

	binary.BigEndian.PutUint64(nonce[:8], id_user)
	copy(nonce[16:24], []byte(password)[:8])
	copy(nonce[8:16], usernameBuff[:])

	return nonce
}

// DA MIGLIORARE
func getUsernameNonceChaCha20FromContact(id_user uint64, password string, cipherNickname []byte) [24]byte {
	var nonce [24]byte

	var usernameBuff [8]byte
	copy(usernameBuff[:], []byte(cipherNickname)[:])

	//TODO
	binary.BigEndian.PutUint64(nonce[:8], id_user)
	copy(nonce[8:16], []byte(password)[:8])
	copy(nonce[8:16], usernameBuff[:])

	return nonce
}

func getContacts(id uint64, password string, db *sql.DB) []Contact {

	query := "SELECT username, nickname, is_blocked FROM contacts WHERE id_user = ?;"
	rows, err := db.Query(query, id)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var cipherUsername []byte
		var cipherNickname []byte
		var is_blocked bool

		err = rows.Scan(&cipherUsername, &cipherNickname, &is_blocked)
		if err != nil {
			return nil
		}

		//Prendo la key
		key := getKeyChaCha20FromContact(id, password)

		// ID
		usernameNonce := getUsernameNonceChaCha20FromContact(id, password, cipherNickname)
		decipherUsernameBytes, err := crypto.DecodeChaCha20(key, usernameNonce, cipherUsername)
		if err != nil {
			return nil
		}

		// NICKNAME
		nicknameNonce := getNicknameNonceChaCha20FromContact(id, password, decipherUsernameBytes)
		decipherNicknameBytes, err := crypto.DecodeChaCha20(key, nicknameNonce, cipherNickname)
		if err != nil {
			return nil
		}

		contacts = append(contacts, Contact{
			username:  string(decipherUsernameBytes),
			nickname:  string(decipherNicknameBytes),
			isBlocked: is_blocked,
		})
	}
	return contacts
}

func AddContact(w http.ResponseWriter, r *http.Request) {
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
	var contactUsername string = r.PostForm.Get(ContactUsername)
	var nickname string = r.PostForm.Get(Nickname)

	if !AuthenticateUser(id, password, db) {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	query := "SELECT id, public_key FROM users WHERE username = ?;"
	rows, err := db.Query(query, contactUsername)
	if err != nil {
		fmt.Fprintf(w, `{"%s": richiesta al database}`, Error)
		return
	}
	defer rows.Close()
	var contactId uint64
	var contactPublicKey []byte
	if rows.Next() {
		if err := rows.Scan(&contactId, &contactPublicKey); err != nil {
			fmt.Fprintf(w, `{"%s": nella lettura del database}`, Error)
			return
		} else if contactId == id {
			fmt.Fprintf(w, `{"%s": non puoi aggiungere te stesso come contatto}`, Error)
			return
		}
	}

	//	CONTROLLO SE IL CONTATTO ESISTE GIà
	contacts := getContacts(id, password, db)
	for _, contact := range contacts {
		if contact.username == contactUsername ||
			contact.nickname == nickname {
			fmt.Fprintf(w, `{"%s": contatto o nickname già esistente}`, Error)
			return
		}
	}

	// INSERISCO NEL DB
	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	//	DA MIGLIORARE
	// CREO IL PRIMO CONTATTO
	key := getKeyChaCha20FromContact(id, password)
	nicknameNonce := getNicknameNonceChaCha20FromContact(id, password, []byte(contactUsername))
	nicknameCipher, err := crypto.EncodeChaCha20(key, nicknameNonce, []byte(nickname))
	if err != nil {
		fmt.Fprintf(w, `{"%s": errore nella cifratura}`, Error)
		return
	}
	usernameNonce := getUsernameNonceChaCha20FromContact(id, password, nicknameCipher)
	usernameCipher, err := crypto.EncodeChaCha20(key, usernameNonce, []byte(contactUsername))
	if err != nil {
		fmt.Fprintf(w, `{"%s": errore nella cifratura}`, Error)
		return
	}

	query = "INSERT INTO contacts (id_user, username, nickname) VALUES (?,?,?);"
	_, err = tx.Exec(query, id, usernameCipher, nicknameCipher)
	if err != nil {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	//CREO IL SECONDO CONTATTO
	cipherId, err := crypto.EncodeECIES256(contactPublicKey, []byte(strconv.FormatUint(id, 10)))
	if err != nil {
		fmt.Fprintf(w, `{"%s": errore nella cifratura}`, Error)
		return
	}

	query = "INSERT INTO contacts (id_user, username, key_flag) VALUES (?,?,?);"
	_, err = tx.Exec(query, contactId, cipherId, 1)
	if err != nil {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	if !createChat(db, "", id, password) ||
		!createChat(db, "", contactId) {

		tx.Rollback()
		fmt.Fprintf(w, `{"%s": Errore creazione dei membri}`, Error)
		return
	}

	err = tx.Commit()
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
	} else {
		fmt.Fprintf(w, `{"%s":%v}`, Success, true)
	}

}

func GetContacts(w http.ResponseWriter, r *http.Request) {
	fmt.Println("GetContacts")

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

	if !AuthenticateUser(id, password, db) {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	contacts := getContacts(id, password, db)
	strContacts := "["
	for i, contact := range contacts {
		if i > 0 {
			strContacts += ","
		}
		strContacts += `{"username": "` + contact.username + `", "nickname": "` + contact.nickname + `", "is_blocked": ` + strconv.FormatBool(contact.isBlocked) + "}"
	}
	strContacts += "]"
	fmt.Fprintf(w, `"%s" : %v `, Contacts, strContacts)
}

func SetBlockState(w http.ResponseWriter, r *http.Request) {
	fmt.Println("SetBlockState")

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
	var contactUsername string = r.PostForm.Get(ContactUsername)
	blockState, err := strconv.ParseBool(r.PostForm.Get(BlockState))
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}

	if !AuthenticateUser(id, password, db) {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	contacts := getContacts(id, password, db)
	var nickname string
	for _, contact := range contacts {
		if contact.username == contactUsername {
			nickname = contact.nickname
		}
	}

	//Cripto lo username per poterlo cercare
	key := getKeyChaCha20FromContact(id, password)
	nickNonce := getNicknameNonceChaCha20FromContact(id, password, []byte(contactUsername))
	cipherNick, err := crypto.EncodeChaCha20(key, nickNonce, []byte(nickname))
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}
	usernameNonce := getUsernameNonceChaCha20FromContact(id, password, cipherNick)
	cipherUsername, err := crypto.EncodeChaCha20(key, usernameNonce, []byte(contactUsername))
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}

	query := "UPDATE contacts SET is_blocked = ? WHERE id_user = ? AND username = ?;"
	_, err = db.Exec(query, blockState, id, cipherUsername)
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v`, Error, err)
	} else {
		fmt.Fprintf(w, `{"%s":%v}`, Success, true)
	}
}

func SetNickname(w http.ResponseWriter, r *http.Request) {
	fmt.Println("SetNickname")

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
	var contactUsername string = r.PostForm.Get(ContactUsername)
	var newNickname string = r.PostForm.Get(Nickname)

	if !AuthenticateUser(id, password, db) {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	contacts := getContacts(id, password, db)
	var nickname string
	for _, contact := range contacts {
		if contact.username == contactUsername {
			nickname = contact.nickname
		}
	}

	//Cripto lo username per poterlo cercare
	key := getKeyChaCha20FromContact(id, password)
	nickNonce := getNicknameNonceChaCha20FromContact(id, password, []byte(contactUsername))
	cipherNick, err := crypto.EncodeChaCha20(key, nickNonce, []byte(nickname))
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}
	usernameNonce := getUsernameNonceChaCha20FromContact(id, password, cipherNick)
	cipherUsername, err := crypto.EncodeChaCha20(key, usernameNonce, []byte(contactUsername))
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}

	newCipherNick, err := crypto.EncodeChaCha20(key, nickNonce, []byte(newNickname))
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}
	usernameNonce = getUsernameNonceChaCha20FromContact(id, password, newCipherNick)
	newCipherUsername, err := crypto.EncodeChaCha20(key, usernameNonce, []byte(contactUsername))
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}

	query := "UPDATE contacts SET username = ?, nickname = ? WHERE id_user = ? AND username = ?;"
	_, err = db.Exec(query, newCipherUsername, newCipherNick, id, cipherUsername)
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v`, Error, err)
	} else {
		fmt.Fprintf(w, `{"%s":%v}`, Success, true)
	}
}

func RemoveContact(w http.ResponseWriter, r *http.Request) {
	fmt.Println("RemoveContact")

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
	var contactUsername string = r.PostForm.Get(ContactUsername)

	if !AuthenticateUser(id, password, db) {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	contacts := getContacts(id, password, db)
	var nickname string
	for _, contact := range contacts {
		if contact.username == contactUsername {
			nickname = contact.nickname
		}
	}

	//Cripto lo username per poterlo cercare
	key := getKeyChaCha20FromContact(id, password)
	nickNonce := getNicknameNonceChaCha20FromContact(id, password, []byte(contactUsername))
	cipherNick, err := crypto.EncodeChaCha20(key, nickNonce, []byte(nickname))
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}
	usernameNonce := getUsernameNonceChaCha20FromContact(id, password, cipherNick)
	cipherUsername, err := crypto.EncodeChaCha20(key, usernameNonce, []byte(contactUsername))
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}

	query := "DELETE FROM contacts WHERE id_user = ? AND username = ?;"
	_, err = db.Exec(query, id, cipherUsername)
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v`, Error, err)
	} else {
		fmt.Fprintf(w, `{"%s":%v}`, Success, true)
	}
}
