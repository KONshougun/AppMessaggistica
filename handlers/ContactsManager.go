package handlers

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/dbData"
)

type Contact struct {
	username  string
	nickname  string
	isBlocked bool
}

func getContacts(id uint64, userKey []byte, db *sql.DB) []Contact {

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
		decipherUsernameBytes, err := crypto.DecryptXChaCha20Poly1305(userKey, usernameNonce, cipherUsername)
		if err != nil {
			return nil
		}
		decipherNicknameBytes, err := crypto.DecryptXChaCha20Poly1305(userKey, nicknameNonce, cipherNickname)
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

func addContact(tx *sql.Tx, idUser uint64, usernameContact, nicknameContact string, userKey []byte) error {

	if userKey == nil {
		userKey = GetUserKey(tx, idUser)
		if userKey == nil {
			return fmt.Errorf("Errore nell'ottenimento della chiave dell'utente")
		}
	}

	usernameNonce := dbData.NewUserNonce(tx, idUser)
	if usernameNonce == nil {
		return fmt.Errorf("Errore nell'ottenimento dello user nonce")
	}
	usernameCipher, err := crypto.EncryptXChaCha20Poly1305(userKey, usernameNonce, []byte(usernameContact))
	if err != nil {
		return err
	}
	usernameHash, err := crypto.EncodeHmacSha256(usernameContact)
	if err != nil {
		return err
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s) 
		VALUES (?,?,?,?);`,
		dbData.Contacts, dbData.IdUser, dbData.UsernameHash, dbData.UsernameContact, dbData.UsernameNonce)
	if _, err = tx.Exec(query, idUser, usernameHash, usernameCipher, usernameNonce); err != nil {
		tx.Rollback()
		return err
	}
	if nicknameContact != "" {
		nicknameNonce := dbData.NewUserNonce(tx, idUser)
		if nicknameNonce != nil {
			return fmt.Errorf("Errore nell'ottenimento del nickname nonce")
		}
		nicknameCipher, err := crypto.EncryptXChaCha20Poly1305(userKey, nicknameNonce, []byte(nicknameContact))
		if err != nil {
			return err
		}
		query = fmt.Sprintf(`
			UPDATE %s
			SET %s = ?, %s = ?;
			WHERE %s = ?, %s = ?`,
			dbData.Contacts, dbData.Nickname, dbData.NicknameNonce, dbData.IdUser, dbData.UsernameHash)
		if _, err = tx.Exec(query, nicknameCipher, nicknameNonce, idUser, usernameHash); err != nil {
			tx.Rollback()
			return err
		}
	}

	return nil
}

func AddContact(conn *Conn, msg string, id uint64, userKey []byte) {
	fmt.Println("AddContact")

	db, err := dbData.StartConnection()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nella lettura del messaggio"))
		return
	}
	defer db.Close()

	msgParams := strings.Split(string(msg), ";")

	var contactUsername string = msgParams[0]
	var nickname string = msgParams[1]

	//CONTROLLO SE STA AGGIUNGENDO SE STESSO
	var contactId uint64
	query := fmt.Sprintf(`SELECT %s FROM %s WHERE %s = ?;`,
		dbData.Id, dbData.Users, dbData.Username)

	if err = db.QueryRow(query, contactUsername).Scan(&contactId); err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore richiesta al database"))
		return
	}
	if contactId == id {
		SendPacket(conn, ERROR, false, []byte("Errore non puoi aggiungere te stesso come contatto"))
		return
	}

	// INSERISCO NEL DB
	tx, err := db.Begin()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	//CREO IL PRIMO MEMBER CHAT
	//	CONTROLLO SE IL CONTATTO ESISTE GIà
	contacts := getContacts(id, userKey, db)
	for _, contact := range contacts {
		if contact.username == contactUsername ||
			contact.nickname == nickname {
			SendPacket(conn, ERROR, false, []byte("Errore contatto o nickname già esistente"))
			return
		}
	}
	if err = addContact(tx, id, contactUsername, nickname, userKey); err != nil {
		fmt.Printf("err: %v\n", err)
		SendPacket(conn, ERROR, false, []byte("Errore nell'aggiunta del primo contatto"))
		return
	}

	//CREO IL SECONDO MEMBER CHAT
	//controllo se già esiste
	var username string
	query = fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", dbData.Username, dbData.Users, dbData.Id)
	if err = db.QueryRow(query, id).Scan(&username); err != nil {
		tx.Rollback()
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
	usernameHash, err := crypto.EncodeHmacSha256(username)
	if err != nil {
		tx.Rollback()
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
	var found bool
	query = fmt.Sprintf("SELECT 1 FROM %s WHERE %s=? AND %s=? LIMIT 1", dbData.Contacts, dbData.IdUser, dbData.UsernameHash)
	err = tx.QueryRow(query, contactId, usernameHash).Scan(&found)
	if err != nil {
		if err != sql.ErrNoRows {
			tx.Rollback()
			SendPacket(conn, ERROR, false, []byte(err.Error()))
			return
		} else {
			if err = addContact(tx, contactId, username, "", nil); err != nil {
				fmt.Printf("err: %v\n", err)
				tx.Rollback()
				SendPacket(conn, ERROR, false, []byte("Errore nell'aggiunta del secondo contatto al contatto"))
				return
			}
		}
	}

	// CONTROLLO SE HANNO GIà UNA CHAT TRA DI LORO
	query = fmt.Sprintf(`
		SELECT 1
		FROM %s
		INNER JOIN %s ON %s = %s
		WHERE %s IS NOT NULL
		GROUP BY %s
		HAVING 
			SUM(%s IN (?,?)) = 2
		`,
		dbData.MembersChat,
		dbData.Chats,
		dbData.Id,
		dbData.IdChat,
		dbData.Name,
		dbData.IdChat,
		dbData.IdUser)

	_, err = tx.Query(query, id, contactId)
	if err != nil && err != sql.ErrNoRows {
		tx.Rollback()
		SendPacket(conn, ERROR, false, []byte("Errore nella ricerca di chat in comune"))
		return
	} else if err == nil {
		if err = tx.Commit(); err != nil {
			SendPacket(conn, ERROR, false, []byte(err.Error()))
		} else {
			SendPacket(conn, SUCCESS, false, []byte{1})
		}
		return
	} else {
		chatId, chatKey := newChat(tx, "")
		if chatId == 0 {
			tx.Rollback()
			SendPacket(conn, ERROR, false, []byte(err.Error()))
			return
		}
		if !newMember(tx, chatId, chatKey, id, userKey) ||
			!newMember(tx, chatId, chatKey, contactId, nil) {
			tx.Rollback()
			SendPacket(conn, ERROR, false, []byte(err.Error()))
			return
		}

		if err = tx.Commit(); err != nil {
			SendPacket(conn, ERROR, false, []byte(err.Error()))
		} else {
			SendPacket(conn, SUCCESS, false, []byte{1})
		}
	}
}

func GetContacts(conn *Conn, msg string, id uint64, userKey []byte) {
	fmt.Println("GetContacts")

	db, err := dbData.StartConnection()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
	defer db.Close()

	/*contacts := getContacts(id, userKey, db)
	//----------------- DA FARE --------------------
	for i, contact := range contacts {
		strContacts += fmt.Sprintf(
			`{"%s": "`+contact.username+`", "%s": "`+contact.nickname+`",
			"%s": `+strconv.FormatBool(contact.isBlocked)+"}",
			Username, Nickname, BlockState)
	}*/
}

func SetBlockState(conn *Conn, msg string, id uint64, userKey []byte) {
	fmt.Println("SetBlockState")

	db, err := dbData.StartConnection()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
	defer db.Close()

	msgParams := strings.Split(string(msg), ";")

	contactUsername := msgParams[0]
	blockState, err := strconv.ParseBool(msgParams[1])
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	//riprendo l'username hashato
	usernameHash, err := crypto.EncodeHmacSha256(contactUsername)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	//CONTROLLO CHE IL CONTATTO ESISTE
	var found bool
	query := fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ? AND %s = ?;", dbData.Contacts, dbData.IdUser, dbData.UsernameHash)
	err = db.QueryRow(query, id, usernameHash).Scan(&found)
	if err == sql.ErrNoRows {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	} else if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	query = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ? AND %s = ?;", dbData.Contacts, dbData.IsBlocked, dbData.IdUser, dbData.UsernameHash)
	if _, err = db.Exec(query, blockState, id, usernameHash); err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
	} else {
		SendPacket(conn, SUCCESS, false, []byte{1})
	}
}

func SetNickname(conn *Conn, msg string, id uint64, userKey []byte) {
	fmt.Println("SetNickname")

	db, err := dbData.StartConnection()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
	defer db.Close()

	msgParams := strings.Split(string(msg), ";")
	contactUsername := msgParams[0]
	newNickname := msgParams[1]

	usernameHash, err := crypto.EncodeHmacSha256(contactUsername)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	var nicknameNonce []byte
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ? AND %s = ?", dbData.NicknameNonce, dbData.Contacts, dbData.IdUser, dbData.UsernameHash)
	err = db.QueryRow(query, id, usernameHash).Scan(&nicknameNonce)
	if err == sql.ErrNoRows {
		SendPacket(conn, ERROR, false, []byte("Contatto non trovato"))
		return
	} else if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	newNicknameNonce := dbData.NewUserNonce(db, id)
	if newNicknameNonce == nil {
		SendPacket(conn, ERROR, false, []byte("Errore nella creazione del nuovo nickname nonce"))
		return
	}
	newCipherNick, err := crypto.EncryptXChaCha20Poly1305(userKey, newNicknameNonce, []byte(newNickname))
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nella cifratura"))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	//AGGIUNGO IL VECCHIIO NONCE AI LOG
	query = fmt.Sprintf("INSERT INTO %s(%s) VALUES (?)", dbData.UsersNoncesLogs, dbData.Nonce)
	_, err = tx.Exec(query, nicknameNonce)
	if err != nil {
		tx.Rollback()
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	//AGGIORNO IL CONTACT
	query = fmt.Sprintf("UPDATE %s SET %s = ?, %s = ? WHERE %s = ? AND %s = ?;", dbData.Contacts, dbData.Nickname, dbData.NicknameNonce, dbData.IdUser, dbData.UsernameHash)
	_, err = tx.Exec(query, newCipherNick, newNicknameNonce, id, usernameHash)
	if err != nil {
		tx.Rollback()
		SendPacket(conn, ERROR, false, []byte(err.Error()))
	} else if err = tx.Commit(); err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
	} else {
		SendPacket(conn, SUCCESS, false, []byte{1})
	}
}

func RemoveContact(conn *Conn, msg string, id uint64, userKey []byte) {
	fmt.Println("RemoveContact")

	db, err := dbData.StartConnection()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
	defer db.Close()

	msgParams := strings.Split(string(msg), ";")
	contactUsername := msgParams[0]

	usernameHash, err := crypto.EncodeHmacSha256(contactUsername)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	var nonces [2][]byte
	query := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s = ? AND %s = ?",
		dbData.UsernameNonce, dbData.NicknameNonce, dbData.Contacts, dbData.IdUser, dbData.UsernameHash)
	err = db.QueryRow(query, id, usernameHash).Scan(&nonces[0], &nonces[1])
	if err == sql.ErrNoRows {
		SendPacket(conn, ERROR, false, []byte("Contatto non trovato"))
		return
	} else if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	tx, err := db.Begin()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	//	------------------- CAMBIARE ---------------------
	//INSERISCO I NONCE NEI LOG
	query = fmt.Sprintf("INSERT INTO %s(%s) VALUES (?)", dbData.UsersNoncesLogs, dbData.Nonce)
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
		SendPacket(conn, ERROR, false, []byte(err.Error()))
	} else if err = tx.Commit(); err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
	} else {
		SendPacket(conn, SUCCESS, false, []byte{1})
	}
}
