package httpRequest

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/dbData"
)

type Contact struct {
	username  string
	nickname  string
	isBlocked bool
}

func getContacts(id uint64, key []byte, db *sql.DB) []Contact {

	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s 
		FROM %s 
		WHERE %s = ?;`,
		dbData.UsernameContact, dbData.UsernameNonce, dbData.Nickname, dbData.NicknameNonce, dbData.IsBlocked, dbData.Contacts, dbData.IdUser)
	rows, err := db.Query(query, id)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var cipherUsername []byte
		var usernameNonce []byte
		var cipherNickname []byte
		var nicknameNonce []byte
		var is_blocked bool

		err = rows.Scan(&cipherUsername, &usernameNonce, &cipherNickname, &nicknameNonce, &is_blocked)
		if err != nil {
			return nil
		}
		decipherUsernameBytes, err := crypto.DecodeChaCha20(key, usernameNonce, cipherUsername)
		if err != nil {
			return nil
		}
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

	key := AuthenticateUser(id, password, db)
	if key == nil {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	//CONTROLLO SE STA AGGIUNGENDO SE STESSO
	var contactId uint64
	var contactPublicKey []byte
	query := fmt.Sprintf(`SELECT %s, %s FROM %s WHERE %s = ?;`,
		dbData.Id, dbData.PubKey, dbData.Users, dbData.Username)
	err = db.QueryRow(query, contactUsername).Scan(&contactId, &contactPublicKey)
	if err != nil {
		fmt.Fprintf(w, `{"%s": richiesta al database}`, Error)
		return
	}
	if contactId == id {
		fmt.Fprintf(w, `{"%s": non puoi aggiungere te stesso come contatto}`, Error)
		return
	}

	//	CONTROLLO SE IL CONTATTO ESISTE GIà
	contacts := getContacts(id, key, db)
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

	// CREO IL PRIMO MEMBER CHAT
	usernameNonce, err := dbData.NewNonce(db, id)
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}
	usernameCipher, err := crypto.EncodeChaCha20(key, usernameNonce, []byte(contactUsername))
	if err != nil {
		fmt.Fprintf(w, `{"%s": errore nella cifratura}`, Error)
		return
	}
	usernameHash, err := crypto.EncodeHmacSha256(contactUsername)
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}

	nicknameNonce, err := dbData.NewNonce(db, id)
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
	}
	nicknameCipher, err := crypto.EncodeChaCha20(key, nicknameNonce, []byte(nickname))
	if err != nil {
		fmt.Fprintf(w, `{"%s": errore nella cifratura}`, Error)
		return
	}

	query = fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s) 
		VALUES (?,?,?,?,?,?);`,
		dbData.Contacts, dbData.IdUser, dbData.UsernameHash, dbData.UsernameContact, dbData.UsernameNonce, dbData.Nickname, dbData.NicknameNonce)
	_, err = tx.Exec(query, id, usernameHash, usernameCipher, usernameNonce, nicknameCipher, nicknameNonce)
	if err != nil {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	//CREO IL SECONDO MEMBER CHAT
	var username string
	query = fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", dbData.Username, dbData.Users, dbData.Id)
	err = tx.QueryRow(query, id).Scan(&username)
	if err != nil {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}
	usernameHash, err = crypto.EncodeHmacSha256(username)
	if err != nil {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	//controllo se già esiste
	var found bool
	query = fmt.Sprintf("SELECT 1 FROM %s WHERE %s=? AND %s=? LIMIT 1", dbData.Contacts, dbData.IdUser, dbData.UsernameHash)
	err = tx.QueryRow(query, contactId, usernameHash).Scan(&found)
	if err == nil {
		err = tx.Commit()
		if err != nil {
			fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		} else {
			fmt.Fprintf(w, `{"%s":%v}`, Success, true)
		}
		return
	} else if err != sql.ErrNoRows {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	cipherUsername, err := crypto.EncodeECIES256(contactPublicKey, []byte(username))
	if err != nil {
		fmt.Fprintf(w, `{"%s": errore nella cifratura}`, Error)
		return
	}

	query = fmt.Sprintf("INSERT INTO %s (%s, %s, %s, %s) VALUES (?,?,?,?);", dbData.Contacts, dbData.IdUser, dbData.UsernameHash, dbData.UsernameContact, dbData.KeyFlag)
	_, err = tx.Exec(query, contactId, usernameHash, cipherUsername, 1)
	if err != nil {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	// ---------------------------- PRIMA DI CREARE UNA CHAT, DEVO VEDERE SE GIà ESISTE
	chatId, chatKey := newChat(tx, "")
	if chatId == 0 {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": errore nella creazione della chat}`, Error)
		return
	}
	if !newMember(tx, chatId, chatKey, id, key, password) ||
		!newMember(tx, chatId, chatKey, contactId, key, "") {

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
	key := AuthenticateUser(id, password, db)
	if key == nil {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	contacts := getContacts(id, key, db)
	strContacts := "["
	for i, contact := range contacts {
		if i > 0 {
			strContacts += ","
		}
		strContacts += fmt.Sprintf(
			`{"%s": "`+contact.username+`", "%s": "`+contact.nickname+`",
			 "%s": `+strconv.FormatBool(contact.isBlocked)+"}",
			Username, Nickname, BlockState)
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

	key := AuthenticateUser(id, password, db)
	if key == nil {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	//riprendo l'username hashato
	usernameHash, err := crypto.EncodeHmacSha256(contactUsername)
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}

	//CONTROLLO CHE IL CONTATTO ESISTE
	var found bool
	query := fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ? AND %s = ?;", Contacts, dbData.IdUser, dbData.UsernameHash)
	err = db.QueryRow(query, id, usernameHash).Scan(&found)
	if err == sql.ErrNoRows {
		fmt.Fprintf(w, `{"%s": "Contatto inesistente"`, Error)
		return
	} else if err != nil {
		fmt.Fprintf(w, `{"%s": %v`, Error, err)
		return
	}

	query = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ? AND %s = ?;", Contacts, dbData.IsBlocked, dbData.IdUser, dbData.UsernameHash)
	_, err = db.Exec(query, blockState, id, usernameHash)
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

	key := AuthenticateUser(id, password, db)
	if key == nil {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	usernameHash, err := crypto.EncodeHmacSha256(contactUsername)
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}

	var nicknameNonce []byte
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ? AND %s = ?", dbData.NicknameNonce, dbData.Contacts, dbData.IdUser, dbData.UsernameHash)
	err = db.QueryRow(query, id, usernameHash).Scan(&nicknameNonce)
	if err == sql.ErrNoRows {
		fmt.Fprintf(w, `{"%s": contatto non trovato}`, Error)
		return
	} else if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}

	newNicknameNonce, err := dbData.NewNonce(db, id)
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}
	newCipherNick, err := crypto.EncodeChaCha20(key, newNicknameNonce, []byte(newNickname))
	if err != nil {
		fmt.Fprintf(w, `{"%s": errore nella cifratura}`, Error)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	//AGGIUNGO IL VECCHIIO NONCE AI LOG
	query = fmt.Sprintf("INSERT INTO %s(%s) VALUES (?)", dbData.NonceLogs, dbData.Nonce)
	_, err = tx.Exec(query, nicknameNonce)
	if err != nil {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	//AGGIORNO IL CONTACT
	query = fmt.Sprintf("UPDATE %s SET %s = ?, %s = ? WHERE %s = ? AND %s = ?;", dbData.Contacts, dbData.Nickname, dbData.NicknameNonce, dbData.IdUser, dbData.UsernameHash)
	_, err = tx.Exec(query, newCipherNick, newNicknameNonce, id, usernameHash)
	if err != nil {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v`, Error, err)
	} else if err = tx.Commit(); err != nil {
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

	key := AuthenticateUser(id, password, db)
	if key == nil {
		fmt.Fprintf(w, `{"%s":"Possibile tentativo di hacking"}`, Error)
		return
	}

	usernameHash, err := crypto.EncodeHmacSha256(contactUsername)
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}

	var nonces [2][]byte
	query := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s = ? AND %s = ?",
		dbData.UsernameNonce, dbData.NicknameNonce, dbData.Contacts, dbData.IdUser, dbData.UsernameHash)
	err = db.QueryRow(query, id, usernameHash).Scan(&nonces[0], &nonces[1])
	if err == sql.ErrNoRows {
		fmt.Fprintf(w, `{"%s": contatto non trovato}`, Error)
		return
	} else if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	//INSERISCO I NONCE NEI LOG
	query = fmt.Sprintf("INSERT INTO %s(%s) VALUES (?)", dbData.NonceLogs, dbData.Nonce)
	for _, nonce := range nonces {
		_, err = tx.Exec(query, nonce)
		if err != nil {
			tx.Rollback()
			return
		}
	}

	query = fmt.Sprintf("DELETE FROM %s WHERE %s = ? AND %s = ?;", dbData.Contacts, dbData.IdUser, dbData.UsernameHash)
	_, err = tx.Exec(query, id, usernameHash)
	if err != nil {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v`, Error, err)
	} else if err = tx.Commit(); err != nil {
		fmt.Fprintf(w, `{"%s": %v`, Error, err)
	} else {
		fmt.Fprintf(w, `{"%s":%v}`, Success, true)
	}
}
