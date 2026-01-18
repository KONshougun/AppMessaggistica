package httpRequest

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/dbData"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// pwdSalt [16]
// cipherPwd [32]
// MKNonce [12]
// cipherMk [48]
// recoveryMK[32]
func getKeys(password string) ([]byte, []byte, []byte, []byte, []byte) {

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
		return nil, nil, nil, nil, nil
	}
	mkNonce := make([]byte, chacha20poly1305.NonceSize)
	rand.Read(mkNonce)
	cipherMk := aead.Seal(nil, mkNonce, MK, nil)
	recoveryMK := crypto.EncryptMK(mkNonce, MK)

	return pwdSalt, pwdHash, mkNonce, cipherMk, recoveryMK
}

func checkPassword(password string, pwdSalt, pwdHash []byte) bool {
	passwordHash := argon2.IDKey([]byte("Login: "+password), pwdSalt, 2, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(pwdHash, passwordHash) == 1
}

// MK
func AuthenticateUser(id uint64, password string, db *sql.DB) []byte {

	var pwdHash, pwdSalt, cipherMk, mkNonce []byte
	query := fmt.Sprintf("SELECT %s, %s, %s, %s FROM %s WHERE %s = ?;", dbData.PwdHash, dbData.PwdSalt, dbData.CipherMk, dbData.MkNonce, dbData.Users, dbData.Id)
	err := db.QueryRow(query, id).Scan(&pwdHash, &pwdSalt, &cipherMk, &mkNonce)
	if err != nil || !checkPassword(password, pwdSalt, pwdHash) {
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

	return MK
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	fmt.Println("SignIn")

	db, err := InitConnections(w, r)
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}
	defer db.Close()

	var username string = r.PostForm.Get(Username)
	var password string = r.PostForm.Get(Password)

	if len(username) < 3 || len(username) > 25 ||
		len(password) < 8 || len(password) > 25 {
		fmt.Fprintf(w, `{"%s":Username o password non validi}`, Error)
		return
	}

	var found bool
	query := fmt.Sprintf("SELECT 1 FROM %s WHERE %s = ? LIMIT 1;", dbData.Users, dbData.Username)
	err = db.QueryRow(query, username).Scan(&found)
	if err == nil {
		fmt.Fprintf(w, `{"%s":Username già esistente}`, Error)
		return
	} else if err != sql.ErrNoRows {
		fmt.Fprintf(w, `{"%s": richiesta al database}`, Error)
		return
	}

	// CREO L'UTENTE
	pwdSalt, passwordHash, mkNonce, cipherMk, recoveryMK := getKeys(password)
	if pwdSalt == nil || passwordHash == nil || mkNonce == nil || cipherMk == nil || recoveryMK == nil {
		fmt.Fprintf(w, `{"%s": errore nella creazione delle chiavi}`, Error)
		return
	}
	privKey, pubKey, err := crypto.GenerateKeysECIES256()
	if err != nil {
		fmt.Fprintf(w, `{"%s": nella generazione delle chiavi}`, Error)
		return
	}
	query = fmt.Sprintf(`
		INSERT INTO %s (%s, %s, %s, %s, %s, %s, %s) 
		VALUES (?,?,?,?,?,?,?);`,
		dbData.Users, dbData.Username, dbData.PwdHash, dbData.PwdSalt, dbData.CipherMk, dbData.MkNonce, dbData.RecoveryMk, dbData.PubKey)
	_, err = db.Exec(query, username, passwordHash, pwdSalt, cipherMk, mkNonce, recoveryMK, pubKey)
	if err != nil {
		fmt.Fprintf(w, `{"%s": nell'inserimento dell'utente nel database}`, Error)
		return
	}

	var id uint64
	query = fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?;", dbData.Id, dbData.Users, dbData.Username)
	err = db.QueryRow(query, username).Scan(&id)
	if err != nil {
		fmt.Fprintf(w, `{"%s":Errore ottenimento dell'id dal database}`, Error)
		return
	}
	fmt.Fprintf(w, `{"%s":"%v","%s":"%x"}`, Id, id, PrivateKey, privKey)

}

func LogIn(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LogIn")

	db, err := InitConnections(w, r)
	if err != nil {
		fmt.Fprintf(w, `{"%s":%v}`, Error, err)
		return
	}
	defer db.Close()

	var username string = r.PostForm.Get(Username)
	var password string = r.PostForm.Get(Password)

	var id uint64
	var pwdSalt, pwdHash []byte
	var failedLogins uint8
	query := fmt.Sprintf(`
		SELECT %s, %s, %s, %s
		FROM %s 
		WHERE %s = ?;`, dbData.Id, dbData.PwdSalt, dbData.PwdHash, dbData.FailedLogins, dbData.Users, dbData.Username)
	err = db.QueryRow(query, username).Scan(&id, &pwdSalt, &pwdHash, &failedLogins)
	if err != nil {
		fmt.Fprintf(w, `{"%s": richiesta al database}`, Error)
		return
	}
	if checkPassword(password, pwdSalt, pwdHash) {
		fmt.Fprintf(w, `{"%s":"%v"}`, Id, id)

		query = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?;", dbData.Users, dbData.FailedLogins, dbData.Id)
		_, err = db.Exec(query, 0, id)
		if err != nil {
			fmt.Println(`Errore: nell'aggiornamento dei tentativi falliti`)
		}
	} else {
		query = fmt.Sprintf("UPDATE %s SET %s = ? WHERE %s = ?;", dbData.Users, dbData.FailedLogins, dbData.Id)
		_, err = db.Exec(query, failedLogins+1, id)
		if err != nil {
			fmt.Println(`Errore: nell'aggiornamento dei tentativi falliti`)
		}
		fmt.Fprintf(w, `{"%s":"Username o password errata"}`, Error)
	}
}

func CheckPassword(w http.ResponseWriter, r *http.Request) {
	fmt.Println("CheckPassword")

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

	var pwdSalt, pwdHash []byte
	query := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s = ?;", dbData.PwdHash, dbData.PwdSalt, dbData.Users, dbData.Id)
	err = db.QueryRow(query, id).Scan(&pwdHash, &pwdSalt)
	if err != nil {
		fmt.Fprintf(w, `{"%s": id errato}`, Error)
		return
	}
	if checkPassword(password, pwdSalt, pwdHash) {
		fmt.Fprintf(w, `{"%s":%v}`, Success, true)
	} else {
		fmt.Fprintf(w, `{"%s":%v}`, Success, false)
	}
}
