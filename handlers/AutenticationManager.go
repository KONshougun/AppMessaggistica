package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/KONshougun/AppMessaggistica/dbData"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// pwdSalt [16]
// cipherPwd [32]
// MKNonce [12]
// cipherMk [48]
// recoveryMK[32]
func getKeys(id uint64, password string) ([]byte, []byte, []byte, []byte, []byte, error) {

	//DERIVO LA PASSWORD
	pwdSalt := make([]byte, 16)
	rand.Read(pwdSalt)
	pwdHash := argon2.IDKey([]byte("Login: "+password), pwdSalt, 2, 64*1024, 4, 32)

	//CREO LA MASTER KEY
	MK := make([]byte, 32)
	rand.Read(MK)
	KEK := argon2.IDKey([]byte(password), pwdSalt, 1, 64*1024, 4, 32)
	aead, err := chacha20poly1305.New(KEK)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	mkNonce := make([]byte, aead.NonceSize())
	rand.Read(mkNonce)
	cipherMk := aead.Seal(nil, mkNonce, MK, nil)
	recoveryMK := EncryptMK(id, mkNonce[:8], MK)
	if recoveryMK == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Errore nella creazione della chiave di recupero")
	}

	return pwdSalt, pwdHash, mkNonce, cipherMk, recoveryMK, nil
}

func checkPassword(password []byte, pwdSalt, pwdHash []byte) bool {
	passwordHash := argon2.IDKey(append([]byte("Login: "), password...), pwdSalt, 2, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(pwdHash, passwordHash) == 1
}

func updateLog(id uint64, db *sql.DB) error {
	//AGGIORNO LAST_LOG DELLO USER
	query := fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ? AND %s IS NOT NULL;", dbData.Users, dbData.LastLog, dbData.Id, dbData.LastLog)
	_, err := db.Exec(query, time.Now(), id)
	return err
}

// MK
func AuthenticateUser(id uint64, password string) []byte {
	db, err := dbData.StartConnection()
	if err != nil {
		return nil
	}

	var pwdHash, pwdSalt, cipherMk, mkNonce []byte
	query := fmt.Sprintf("SELECT %s, %s, %s, %s FROM %s WHERE %s = ?;", dbData.PwdHash, dbData.PwdSalt, dbData.CipherMk, dbData.MkNonce, dbData.Users, dbData.Id)
	err = db.QueryRow(query, id).Scan(&pwdHash, &pwdSalt, &cipherMk, &mkNonce)
	if err != nil || !checkPassword([]byte(password), pwdSalt, pwdHash) {
		return nil
	}

	KEK := argon2.IDKey([]byte(password), pwdSalt, 1, 64*1024, 4, 32)
	aead, err := chacha20poly1305.New(KEK)
	if err != nil {
		return nil
	}
	MK, err := aead.Open(nil, mkNonce, cipherMk, nil)
	if err != nil {
		return nil
	}

	if updateLog(id, db) != nil {
		return nil
	}
	return MK
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

func SignIn(conn *Conn, msg string, id uint64) (uint64, string) {
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
	err = db.QueryRow(query, username).Scan(&found)
	if err == nil {
		SendPacket(conn, ERROR, false, []byte("Username già esistente"))
		return 0, ""
	} else if err != sql.ErrNoRows {
		SendPacket(conn, ERROR, false, []byte("Errore nella richiesta al database"))
		return 0, ""
	}

	// CREO L'UTENTE
	pwdSalt, passwordHash, mkNonce, cipherMk, recoveryMK, err := getKeys(id, password)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nella creazione delle chiavi"))
		fmt.Printf("err: %v\n", err)
		return 0, ""
	}

	query = fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s, %s) 
		VALUES (?,?,?,?,?,?,?);`,
		dbData.Users, dbData.Username, dbData.LastLog, dbData.PwdHash, dbData.PwdSalt, dbData.CipherMk, dbData.MkNonce, dbData.RecoveryMk)
	_, err = db.Exec(query, username, time.Now(), passwordHash, pwdSalt, cipherMk, mkNonce, recoveryMK)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore nell'inserimento dell'utente nel database"))
		fmt.Printf("err: %v\n", err)
		return 0, ""
	}

	var idApp uint64
	query = fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?;", dbData.Id, dbData.Users, dbData.Username)
	err = db.QueryRow(query, username).Scan(&idApp)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore ottenimento dell'id dal database"))
		return 0, ""
	}

	//FORSE DA TOGLIERE  (FORSE NON è DA TOGLIERE) (SICURAMENTE I DATI SONO DA CRIPTARE)
	SendPacket(conn, SIGN_RESPONSE, false, []byte(fmt.Sprintf("%v", idApp)))

	return id, password
}

func SignUp(conn *Conn, msg string, id uint64) (uint64, string) {
	fmt.Println("SignUp")

	db, username, password, err := signHandler(msg)
	if err != nil ||
		len(username) < 3 || len(username) > 25 ||
		len(password) < 8 || len(password) > 25 {
		SendPacket(conn, ERROR, false, []byte("Errore nella lettura del messaggio"))
		return 0, ""
	}
	defer db.Close()

	var idApp uint64
	var pwdSalt, pwdHash []byte
	var failedLogins uint8
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s
		FROM %s 
		WHERE %s = ?;`, dbData.Id, dbData.PwdSalt, dbData.PwdHash, dbData.FailedLogins, dbData.Users, dbData.Username)
	err = db.QueryRow(query, username).Scan(&idApp, &pwdSalt, &pwdHash, &failedLogins)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Errore ottenimento dell'id dal database"))
		return 0, ""
	}

	if checkPassword([]byte(password), pwdSalt, pwdHash) {
		query = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?;", dbData.Users, dbData.FailedLogins, dbData.Id)
		_, err = db.Exec(query, 0, idApp)
		if err != nil {
			SendPacket(conn, ERROR, false, []byte("Errore nell'aggiornamento dei tentativi falliti"))
			return 0, ""
		}
		if updateLog(idApp, db) != nil {
			SendPacket(conn, ERROR, false, []byte("Errore richiesta al database"))
			return 0, ""
		}
	} else {
		query = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?;", dbData.Users, dbData.FailedLogins, dbData.Id)
		_, err = db.Exec(query, failedLogins+1, idApp)
		if err != nil {
			SendPacket(conn, ERROR, false, []byte("Errore nell'aggiornamento dei tentativi falliti"))
			return 0, ""
		}
		SendPacket(conn, ERROR, false, []byte("Errore Username o password errata"))
		return 0, ""
	}

	//FORSE DA TOGLIERE
	SendPacket(conn, SIGN_RESPONSE, false, []byte(fmt.Sprintf("%v", idApp)))
	return id, password
}

func CheckPassword(conn *Conn, password string, id uint64) {
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
