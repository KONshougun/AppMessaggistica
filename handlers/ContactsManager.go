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
	Username  string `json:"username"`
	Nickname  string `json:"nickname"`
	LastLog   string `json:"lastLog"`
	IsBlocked bool   `json:"isBlocked"`
}

func getContacts(id int64, userKey []byte, db *sql.DB) ([]Contact, error) {

	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s, %s 
		FROM %s c
		INNER JOIN %s ON %s = %s
		WHERE c.%s = ?;`,
		dbData.ContactUsername, dbData.Nickname, dbData.NicknameNonce, dbData.IsBlocked, dbData.LastLog,
		dbData.Contacts, dbData.Users, dbData.Username, dbData.ContactUsername, dbData.Id)
	rows, err := db.Query(query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []Contact
	for rows.Next() {
		var contactUsername string
		var cipherNickname []byte
		var nicknameNonce []byte
		var is_blocked bool
		var lastLogStr string

		var lastLog sql.NullString

		err = rows.Scan(&contactUsername, &cipherNickname, &nicknameNonce, &is_blocked, &lastLog)
		if err != nil {
			return nil, err
		}
		decipherNicknameBytes, err := crypto.DecryptXChaCha20Poly1305(userKey, nicknameNonce, cipherNickname)
		if err != nil {
			return nil, err
		}
		if lastLog.Valid {
			lastLogStr = lastLog.String
		} else {
			lastLogStr = ""
		}

		contacts = append(contacts, Contact{
			Username:  contactUsername,
			Nickname:  string(decipherNicknameBytes),
			IsBlocked: is_blocked,
			LastLog:   lastLogStr,
		})
	}
	return contacts, nil
}

func addContact(tx *sql.Tx, idUser int64, usernameContact, nicknameContact string, key []byte) error {

	if len(key) == 32 {
		nicknameNonce := dbData.NewUserNonce(tx, idUser)
		if nicknameNonce == nil {
			return fmt.Errorf("Errore nell'ottenimento di un nonce per il nickname")
		}
		nicknameCipher, err := crypto.EncryptXChaCha20Poly1305(key, nicknameNonce, []byte(nicknameContact))
		if err != nil {
			return err
		}

		query := fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s) 
		VALUES (?, ?, ?, ?);`,
			dbData.Contacts, dbData.Id, dbData.ContactUsername, dbData.Nickname, dbData.NicknameNonce)
		if _, err = tx.Exec(query, idUser, usernameContact, nicknameCipher, nicknameNonce); err != nil {
			tx.Rollback()
			return err
		}
	} else {
		return fmt.Errorf("Chiave non valida")
	}
	return nil
}

func AddContact(conn *Conn, msg string, id int64, userKey []byte) {
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
	var contactId int64
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
	contacts, err := getContacts(id, userKey, db)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
	for _, contact := range contacts {
		if contact.Username == contactUsername ||
			contact.Nickname == nickname {
			SendPacket(conn, ERROR, false, []byte("Errore contatto o nickname già esistente"))
			return
		}
	}
	if err = addContact(tx, id, contactUsername, nickname, userKey); err != nil {
		fmt.Printf("err: %v\n", err)
		SendPacket(conn, ERROR, false, []byte("Errore nell'aggiunta del primo contatto"))
		return
	}

	// CONTROLLO SE HANNO GIà UNA CHAT TRA DI LORO
	var count int
	query = fmt.Sprintf(`
		SELECT COUNT(*)
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

	err = tx.QueryRow(query, id, contactId).Scan(&count)
	if err == nil || err == sql.ErrNoRows {
		switch count {
		case 1:
			if err = tx.Commit(); err != nil {
				SendPacket(conn, ERROR, false, []byte(err.Error()))
			} else {
				SendPacket(conn, SUCCESS, false, []byte{1})
			}
			return
		case 0:
			chatId, chatKey, err := newChat(tx, "")
			if err != nil {
				tx.Rollback()
				SendPacket(conn, ERROR, false, []byte(err.Error()))
				return
			}

			//prendo la chiave pubblica del contatto
			var pubKey []byte
			query = fmt.Sprintf("SELECT %s FROM %s WHERE %s=?", dbData.PubKey, dbData.Users, dbData.Id)
			err = tx.QueryRow(query, contactId).Scan(&pubKey)
			if err != nil {
				tx.Rollback()
				SendPacket(conn, ERROR, false, []byte(err.Error()))
				return
			}
			if !newMember(tx, chatId, chatKey, id, userKey) ||
				!newMember(tx, chatId, chatKey, contactId, pubKey) {
				tx.Rollback()
				SendPacket(conn, ERROR, false, []byte("Errore nella creazione dei due membri delle chat"))
				return
			}

			if err = tx.Commit(); err != nil {
				SendPacket(conn, ERROR, false, []byte(err.Error()))
			} else {
				SendPacket(conn, SUCCESS, false, []byte{1})
			}
		default:
			fmt.Println("Non so come sia possibile")
			tx.Rollback()
			SendPacket(conn, ERROR, false, []byte("Anomalia nella ricerca della chat"))
			return
		}
	} else {
		tx.Rollback()
		SendPacket(conn, ERROR, false, []byte("Errore nella ricerca di chat in comune"))
		return
	}
}

func GetContacts(conn *Conn, id int64, userKey []byte) {
	fmt.Println("GetContacts")

	db, err := dbData.StartConnection()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
	defer db.Close()

	if err = SendPacket(conn, LOAD_START, false, nil); err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	contacts, err := getContacts(id, userKey, db)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	var buffer strings.Builder
	for _, contact := range contacts {
		fmt.Fprintf(&buffer, "%s,%s,%s,%t", contact.Username, contact.Nickname, contact.LastLog, contact.IsBlocked)
		//fmt.Printf("contact: %v\n", contact)
		if buffer.Len() > 5000 {
			SendPacket(conn, PROGRESS, true, []byte(buffer.String()))
			buffer.Reset()
		} else {
			buffer.Write([]byte(";"))
		}
	}
	if buffer.Len() > 0 {
		SendPacket(conn, PROGRESS, true, []byte(buffer.String()))
	}

	if err = SendPacket(conn, LOAD_END, false, nil); err != nil {
		fmt.Printf("err: %v\n", err)
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
}

func SetBlockState(conn *Conn, msg string, id int64, userKey []byte) {
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

	//CONTROLLO CHE IL CONTATTO ESISTE
	var found bool
	query := fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ? AND %s = ?;", dbData.Contacts, dbData.IdUser, dbData.ContactUsername)
	err = db.QueryRow(query, id, contactUsername).Scan(&found)
	if err == sql.ErrNoRows {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	} else if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}

	query = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ? AND %s = ?;", dbData.Contacts, dbData.IsBlocked, dbData.IdUser, dbData.ContactUsername)
	if _, err = db.Exec(query, blockState, id, contactUsername); err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
	} else {
		SendPacket(conn, SUCCESS, false, []byte{1})
	}
}

func SetNickname(conn *Conn, msg string, id int64, userKey []byte) {
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

	var nicknameNonce []byte
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ? AND %s = ?", dbData.NicknameNonce, dbData.Contacts, dbData.IdUser, dbData.ContactUsername)
	err = db.QueryRow(query, id, contactUsername).Scan(&nicknameNonce)
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

	newNicknameNonce := dbData.NewUserNonce(tx, id)
	if newNicknameNonce == nil {
		SendPacket(conn, ERROR, false, []byte("Errore nella creazione del nuovo nickname nonce"))
		return
	}
	newCipherNick, err := crypto.EncryptXChaCha20Poly1305(userKey, newNicknameNonce, []byte(newNickname))
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nella cifratura"))
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
	query = fmt.Sprintf("UPDATE %s SET %s = ?, %s = ? WHERE %s = ? AND %s = ?;", dbData.Contacts, dbData.Nickname, dbData.NicknameNonce, dbData.IdUser, dbData.ContactUsername)
	_, err = tx.Exec(query, newCipherNick, newNicknameNonce, id, contactUsername)
	if err != nil {
		tx.Rollback()
		SendPacket(conn, ERROR, false, []byte(err.Error()))
	} else if err = tx.Commit(); err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
	} else {
		SendPacket(conn, SUCCESS, false, []byte{1})
	}
}

func RemoveContact(conn *Conn, msg string, id int64, userKey []byte) {
	fmt.Println("RemoveContact")

	db, err := dbData.StartConnection()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return
	}
	defer db.Close()

	msgParams := strings.Split(string(msg), ";")
	contactUsername := msgParams[0]

	var nonce []byte
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ? AND %s = ?",
		dbData.NicknameNonce, dbData.Contacts, dbData.IdUser, dbData.ContactUsername)
	err = db.QueryRow(query, id, contactUsername).Scan(&nonce)
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
	_, err = tx.Exec(query, nonce)
	if err != nil {
		tx.Rollback()
		return
	}

	query = fmt.Sprintf("DELETE FROM %s WHERE %s = ? AND %s = ?;", dbData.Contacts, dbData.IdUser, dbData.ContactUsername)
	_, err = tx.Exec(query, id, contactUsername)
	if err != nil {
		tx.Rollback()
		SendPacket(conn, ERROR, false, []byte(err.Error()))
	} else if err = tx.Commit(); err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
	} else {
		SendPacket(conn, SUCCESS, false, []byte{1})
	}
}
