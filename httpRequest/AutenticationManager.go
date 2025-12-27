package httpRequest

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"github.com/KONshougun/AppMessaggistica/crypto"
)

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
		len(password) < 8 || len(password) > 50 {
		fmt.Fprintf(w, `{"%s":Username o password non validi}`, Error)
		return
	}

	query := "SELECT id FROM users WHERE username = ?;"
	rows, err := db.Query(query, username)
	if err != nil {
		fmt.Fprintf(w, `{"%s": richiesta al database}`, Error)
		return
	}
	defer rows.Close()
	if rows.Next() {
		fmt.Fprintf(w, `{"%s":Username già esistente}`, Error)
		return
	}

	// CREO L'UTENTE
	passwordHash, err := crypto.HashPassword([]byte(password))
	if err != nil {
		fmt.Fprintf(w, `{"%s": nell'hashing della password}`, Error)
		return
	}
	privKey, pubKey, err := crypto.GenerateKeysECIES256()
	if err != nil {
		fmt.Fprintf(w, `{"%s": nella generazione delle chiavi}`, Error)
		return
	}
	query = "INSERT INTO users (username, password_hash, public_key) VALUES (?,?,?);"
	_, err = db.Exec(query, username, passwordHash, pubKey)
	if err != nil {
		fmt.Fprintf(w, `{"%s": nell'inserimento dell'utente nel database}`, Error)
		return
	}

	query = "SELECT id FROM users WHERE username = ?;"
	rows, err = db.Query(query, username)
	if err != nil {
		fmt.Fprintf(w, `{"%s": ottenimento dell'id dal database}`, Error)
		return
	}
	defer rows.Close()

	if rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			fmt.Fprintf(w, `{"%s": nella lettura del database}`, Error)
			return
		}
		fmt.Fprintf(w, `{"%s":"%v","%s":"%x"}`, Id, id, PrivateKey, privKey)
	}

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

	query := "SELECT id, password_hash, failed_logins FROM users WHERE username = ?;"
	rows, err := db.Query(query, username)
	if err != nil {
		fmt.Fprintf(w, `{"%s": richiesta al database}`, Error)
		return
	}
	defer rows.Close()

	if rows.Next() {
		var id uint64
		var passwordHash []byte
		var failedLogins uint8
		if err := rows.Scan(&id, &passwordHash, &failedLogins); err != nil {
			fmt.Fprintf(w, `{"%s": nella lettura del database}`, Error)
			return
		} else if crypto.CheckPasswordHash([]byte(password), passwordHash[:]) {
			fmt.Fprintf(w, `{"%s":"%v"}`, Id, id)

			query = "UPDATE users SET failed_logins = ? WHERE id = ?;"
			_, err = db.Exec(query, 0, id)
			if err != nil {
				fmt.Println(`Errore: nell'aggiornamento dei tentativi falliti`)
			}

		} else {
			query = "UPDATE users SET failed_logins = ? WHERE id = ?;"
			_, err = db.Exec(query, failedLogins+1, id)
			if err != nil {
				fmt.Println(`Errore: nell'aggiornamento dei tentativi falliti`)
			}
			fmt.Fprintf(w, `{"%s":"Username o password errata"}`, Error)
		}
	}
}

func AuthenticateUser(id uint64, password string, db *sql.DB) bool {
	query := "SELECT password_hash FROM users WHERE id = ?;"
	rows, err := db.Query(query, id)
	if err != nil {
		return false
	}
	defer rows.Close()

	if rows.Next() {
		var passwordHash []byte
		if err := rows.Scan(&passwordHash); err != nil {
			return false
		} else if crypto.CheckPasswordHash([]byte(password), passwordHash[:]) {
			return true
		}
	}
	return false
}

func CheckPassword(w http.ResponseWriter, r *http.Request) {
	fmt.Println("CheckPawword")

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

	query := "SELECT password_hash FROM users WHERE id = ?;"
	rows, err := db.Query(query, id)
	if err != nil {
		fmt.Fprintf(w, `{"%s": richiesta al database}`, Error)
		return
	}
	defer rows.Close()

	if rows.Next() {

		var passwordHash []byte
		if err := rows.Scan(&passwordHash); err != nil {
			fmt.Fprintf(w, `{"%s": nella lettura del database}`, Error)
			return
		} else if crypto.CheckPasswordHash([]byte(password), passwordHash[:]) {
			fmt.Fprintf(w, `{"%s":%v}`, Success, true)
		} else {
			fmt.Fprintf(w, `{"%s":%v}`, Success, false)
		}
		return
	}
	fmt.Fprintf(w, `{"%s":"ID o password errata"}`, Error)
}
