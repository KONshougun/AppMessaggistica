package httpRequest

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"

	"github.com/KONshougun/AppMessaggistica/crypto"
)

func getKeyChaCha20FromContact(id_user uint64, password string) [32]byte {
	var key [32]byte

	binary.BigEndian.PutUint64(key[:8], id_user)
	for i := 1; i <= 3; i++ {
		copy(key[i*8:(i+1)*8], []byte(password)[:8])
	}
	return key
}
func getNicknameNonceChaCha20FromContact(id_user uint64, password string, contactId uint64) [24]byte {
	var nonce [24]byte

	binary.BigEndian.PutUint64(nonce[:8], id_user)
	binary.BigEndian.PutUint64(nonce[8:16], contactId)
	copy(nonce[16:24], []byte(password)[:8])

	return nonce
}
func getIdNonceChaCha20FromContact(id_user uint64, password string) [24]byte {
	var nonce [24]byte

	//TODO
	binary.BigEndian.PutUint64(nonce[:8], id_user)
	binary.BigEndian.PutUint32(nonce[8:12], uint32(id_user))
	copy(nonce[12:16], []byte(password)[:4])
	copy(nonce[16:24], []byte(password)[:8])

	return nonce
}
func AddContact(w http.ResponseWriter, r *http.Request) {
	fmt.Println("AddContact")

	db, err := InitConnections(w, r)
	if err != nil {
		return
	}
	defer db.Close()

	id, err := strconv.ParseUint(r.PostForm.Get(ID), 10, 64)
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

	//	DEVO CONTROLLARE SE IL CONTATTO ESISTE GIà

	// INSERISCO NEL DB
	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	// CREO IL PRIMO CONTATTO
	key := getKeyChaCha20FromContact(id, password)
	nicknameNonce := getNicknameNonceChaCha20FromContact(id, password, contactId)
	nicknameChiper, err := crypto.EncodeChaCha20(key, nicknameNonce, []byte(nickname))
	if err != nil {
		fmt.Fprintf(w, `{"%s": errore nella cifratura}`, Error)
		return
	}
	idNonce := getIdNonceChaCha20FromContact(id, password)
	idChiper, err := crypto.EncodeChaCha20(key, idNonce, []byte(strconv.FormatUint(contactId, 10)))
	if err != nil {
		fmt.Fprintf(w, `{"%s": errore nella cifratura}`, Error)
		return
	}

	query = "INSERT INTO contacts (id_user, id_contact, nickname) VALUES (?,?,?);"
	_, err = tx.Exec(query, id, idChiper, nicknameChiper)
	if err != nil {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}

	//CREO IL SECONDO CONTATTO
	chiperId, err := crypto.EncodeECIES256(contactPublicKey, []byte(strconv.FormatUint(id, 10)))
	if err != nil {
		fmt.Fprintf(w, `{"%s": errore nella cifratura}`, Error)
		return
	}

	query = "INSERT INTO contacts (id_user, id_contact) VALUES (?,?);"
	_, err = tx.Exec(query, contactId, chiperId)
	if err != nil {
		tx.Rollback()
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
		return
	}
	err = tx.Commit()
	if err != nil {
		fmt.Fprintf(w, `{"%s": %v}`, Error, err)
	} else {
		fmt.Fprintf(w, `{"%s":%v}`, Success, true)
	}
}
