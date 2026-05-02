package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/dbData"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// pwdSalt [16]
// cipherPwd [32]
// MKNonce [12]
// cipherMk [48]
// privKey = 32B
// pubKey = 33B (compressa)
func getKeys(password string) ([]byte, []byte, []byte, []byte, []byte, []byte, error) {

	//DERIVO LA PASSWORD
	pwdSalt := make([]byte, 16)
	rand.Read(pwdSalt)
	pwdHash := argon2.IDKey([]byte("Login: "+password), pwdSalt, 2, 64*1024, 4, 32)

	//CREO LA MASTER KEY
	MK := make([]byte, 32)
	rand.Read(MK)
	KEK := argon2.IDKey([]byte(password), pwdSalt, 1, 64*1024, 4, 32)
	aead, err := chacha20poly1305.NewX(KEK)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	mkNonce := make([]byte, aead.NonceSize())
	rand.Read(mkNonce)
	cipherMk := aead.Seal(nil, mkNonce, MK, nil)

	privKey, pubKey, err := crypto.GenerateKeysECIES256()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("Errore nella creazione delle chiavi asimmetriche")
	}

	return pwdSalt, pwdHash, mkNonce, cipherMk, privKey, pubKey, nil
}

func checkPassword(password []byte, pwdSalt, pwdHash []byte) bool {
	passwordHash := argon2.IDKey(append([]byte("Login: "), password...), pwdSalt, 2, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(pwdHash, passwordHash) == 1
}

func updateLog(id int64, db *sql.DB) error {
	//AGGIORNO LAST_LOG DELLO USER
	query := fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ? AND %s IS NOT NULL;", dbData.Users, dbData.LastLog, dbData.Id, dbData.LastLog)
	_, err := db.Exec(query, time.Now(), id)
	return err
}

// MK
func AuthenticateUser(id int64, password string) ([]byte, error) {
	db, err := dbData.StartConnection()
	if err != nil {
		return nil, err
	}

	var pwdHash, pwdSalt, cipherMk, mkNonce []byte
	query := fmt.Sprintf("SELECT %s, %s, %s, %s FROM %s WHERE %s = ?;",
		dbData.PwdHash, dbData.PwdSalt, dbData.CipherMk, dbData.MkNonce, dbData.Users, dbData.Id)
	err = db.QueryRow(query, id).Scan(&pwdHash, &pwdSalt, &cipherMk, &mkNonce)
	if err != nil || !checkPassword([]byte(password), pwdSalt, pwdHash) {
		return nil, err
	}

	KEK := argon2.IDKey([]byte(password), pwdSalt, 1, 64*1024, 4, 32)
	aead, err := chacha20poly1305.NewX(KEK)
	if err != nil {
		return nil, err
	}
	MK, err := aead.Open(nil, mkNonce, cipherMk, nil)
	if err != nil {
		return nil, err
	}

	if updateLog(id, db) != nil {
		return nil, err
	}
	return MK, nil
}

func signHandler(msg string) (*sql.DB, string, string, error) {
	db, err := dbData.StartConnection()
	if err != nil {
		return nil, "", "", err
	}
	msgParams := strings.Split(string(msg), ";")

	var username string = msgParams[0]
	var password string = msgParams[1]

	return db, username, password, nil
}

func SignIn(conn *Conn, msg string) (int64, string) {
	fmt.Println("SignIn")

	db, username, password, err := signHandler(msg)
	if err != nil ||
		len(username) < 3 || len(username) > 25 ||
		len(password) < 8 || len(password) > 25 {
		SendPacket(conn, ERROR, false, []byte("Errore nella lettura del messaggio"))
		return 0, ""
	}
	defer db.Close()

	var found bool
	query := fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ? LIMIT 1;", dbData.Users, dbData.Username)
	if err = db.QueryRow(query, username).Scan(&found); err == nil {
		SendPacket(conn, ERROR, false, []byte("Username già esistente"))
		return 0, ""
	} else if err != sql.ErrNoRows {
		SendPacket(conn, ERROR, false, []byte("Errore nella richiesta al database"))
		return 0, ""
	}

	// CREO L'UTENTE
	tx, err := db.Begin()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte(err.Error()))
		return 0, ""
	}

	query = fmt.Sprintf(`
		INSERT INTO %s (%s, %s) 
		VALUES (?,?);`,
		dbData.Users, dbData.Username, dbData.LastLog)
	row, err := tx.Exec(query, username, time.Now())
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nell'inserimento dell'utente nel database"))
		fmt.Printf("err: %v\n", err)
		return 0, ""
	}
	id, err := row.LastInsertId()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nell'inserimento dell'utente nel database"))
		fmt.Printf("err: %v\n", err)
		return 0, ""
	}

	pwdSalt, passwordHash, mkNonce, cipherMk, privKey, pubKey, err := getKeys(password)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nella creazione delle chiavi"))
		fmt.Printf("err: %v\n", err)
		return 0, ""
	}
	query = fmt.Sprintf(`
		UPDATE %s
		SET %s = ?, %s = ?, %s = ?, %s = ?, %s = ?
		WHERE %s = ?;`,
		dbData.Users, dbData.PwdHash, dbData.PwdSalt, dbData.CipherMk, dbData.MkNonce, dbData.PubKey, dbData.Id)
	_, err = tx.Exec(query, passwordHash, pwdSalt, cipherMk, mkNonce, pubKey, id)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nell'inserimento dell'utente nel database"))
		fmt.Printf("err: %v\n", err)
		return 0, ""
	}

	if err = SendPacket(conn, SIGN_RESPONSE, true, fmt.Appendf(nil, "%v;%v", id, privKey)); err != nil {
		fmt.Printf("err: %v\n", err)
	}
	response, _, err := ReadHeader(conn)
	if err == nil && response == SUCCESS {
		if err = tx.Commit(); err != nil {
			return 0, ""
		} else {
			return id, password
		}
	} else {
		return 0, ""
	}
}

// DA TOGLIERE
func SignUp(conn *Conn, msg string) (int64, string) {
	fmt.Println("SignUp")

	db, username, password, err := signHandler(msg)
	if err != nil ||
		len(username) < 3 || len(username) > 25 ||
		len(password) < 8 || len(password) > 25 {
		SendPacket(conn, ERROR, false, []byte("Errore nella lettura del messaggio"))
		return 0, ""
	}
	defer db.Close()

	var id int64
	var pwdSalt, pwdHash []byte
	var failedLogins uint8
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s
		FROM %s 
		WHERE %s = ?;`, dbData.Id, dbData.PwdSalt, dbData.PwdHash, dbData.FailedLogins, dbData.Users, dbData.Username)
	err = db.QueryRow(query, username).Scan(&id, &pwdSalt, &pwdHash, &failedLogins)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore ottenimento dell'id dal database"))
		return 0, ""
	}

	if checkPassword([]byte(password), pwdSalt, pwdHash) {
		query = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?;", dbData.Users, dbData.FailedLogins, dbData.Id)
		_, err = db.Exec(query, 0, id)
		if err != nil {
			SendPacket(conn, ERROR, false, []byte("Errore nell'aggiornamento dei tentativi falliti"))
			return 0, ""
		}
		if updateLog(id, db) != nil {
			SendPacket(conn, ERROR, false, []byte("Errore richiesta al database"))
			return 0, ""
		}
	} else {
		query = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?;", dbData.Users, dbData.FailedLogins, dbData.Id)
		_, err = db.Exec(query, failedLogins+1, id)
		if err != nil {
			SendPacket(conn, ERROR, false, []byte("Errore nell'aggiornamento dei tentativi falliti"))
			return 0, ""
		}
		SendPacket(conn, ERROR, false, []byte("Errore Username o password errata"))
		return 0, ""
	}

	SendPacket(conn, SIGN_RESPONSE, false, []byte(fmt.Sprintf("%v", id)))

	response, _, err := ReadHeader(conn)
	if err == nil && response == SUCCESS {
		return id, password
	} else {
		return 0, ""
	}
}
func CheckPassword(conn *Conn, password string, id int64) {
	fmt.Println("CheckPassword")

	db, err := dbData.StartConnection()
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore connessione al database"))
		return
	}
	defer db.Close()

	var pwdSalt, pwdHash []byte
	query := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s = ?;", dbData.PwdHash, dbData.PwdSalt, dbData.Users, dbData.Id)
	err = db.QueryRow(query, id).Scan(&pwdHash, &pwdSalt)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore id errato"))
		return
	}
	if checkPassword([]byte(password), pwdSalt, pwdHash) {
		SendPacket(conn, SUCCESS, false, []byte{1})
	} else {
		SendPacket(conn, SUCCESS, false, []byte{0})
	}
}
