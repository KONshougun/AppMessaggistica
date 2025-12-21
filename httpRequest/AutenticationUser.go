package httpRequest

import (
	"fmt"
	"net/http"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/databaseConnection"
)

const (
	Username        string = "Username"
	ID              string = "ID"
	Password        string = "Password"
	PrivateKey      string = "PrivateKey"
	ContactUsername string = "ContactUsername"
	Contacts        string = "Contacts"
	Nickname        string = "Nickname"
	Text            string = "Text"
	Error           string = "Error"
)

func SignIn(w http.ResponseWriter, r *http.Request) {
	fmt.Println("SignIn")

	// Assicurati che sia una POST
	if r.Method != http.MethodPost {
		fmt.Fprintf(w, `{"%s":Metodo non consentito}`, Error)
		return
	}

	// Parse dei dati form-urlencoded
	err := r.ParseForm()
	if err != nil {
		fmt.Fprintf(w, `{"%s": nel parsing del form}`, Error)
		return
	}

	var username string = r.PostForm.Get(Username)
	var password string = r.PostForm.Get(Password)

	if len(username) < 3 || len(username) > 25 ||
		len(password) < 8 || len(password) > 50 {
		fmt.Fprintf(w, `{"%s":Username o password non validi}`, Error)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	db, err := databaseConnection.StartConnection()
	if err != nil {
		fmt.Fprintf(w, `{"%s": connessione al database}`, Error)
	}
	defer db.Close()

	query := "SELECT id FROM users WHERE username = ?;"
	rows, err := db.Query(query, username)
	if err != nil {
		fmt.Fprintf(w, `{"%s": richiesta al database}`, Error)
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
	}
	defer rows.Close()
	if rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			fmt.Fprintf(w, `{"%s": nella lettura del database}`, Error)
		}
		fmt.Fprintf(w, `{"%s":"%v","%s":"%x"}`, ID, id, PrivateKey, privKey)
		if rows.Next() {
			fmt.Fprintf(w, `{"%s": più utenti con lo stesso username}`, Error)
		}
	}

}

func LogIn(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LogIn")

	// Assicurati che sia una POST
	if r.Method != http.MethodPost {
		fmt.Fprintf(w, "Metodo non consentito", Error)
		return
	}

	// Parse dei dati form-urlencoded
	err := r.ParseForm()
	if err != nil {
		fmt.Fprintf(w, `{"%s": nel parsing del form}`, Error)
		return
	}

	var username string = r.PostForm.Get(Username)
	var password string = r.PostForm.Get(Password)

	w.Header().Set("Content-Type", "application/json")
	db, err := databaseConnection.StartConnection()
	if err != nil {
		fmt.Fprintf(w, `{"%s": connessione al database}`, Error)
	}
	defer db.Close()

	query := "SELECT id, password_hash FROM users WHERE username = ?;"
	rows, err := db.Query(query, username)
	if err != nil {
		fmt.Fprintf(w, `{"%s": richiesta al database}`, Error)
	}
	defer rows.Close()
	if rows.Next() {
		var id uint64
		var passwordHash []byte
		if err := rows.Scan(&id, &passwordHash); err != nil {
			fmt.Fprintf(w, `{"%s": nella lettura del database}`, Error)
		}
		if crypto.CheckPasswordHash([]byte(password), passwordHash[:]) {
			fmt.Fprintf(w, `{"%s":"%v"}`, ID, id)
		} else {
			fmt.Fprintf(w, `{"%s":"Username o password errata"}`, Error)
		}
		if rows.Next() {
			fmt.Fprintf(w, `{"%s": più utenti con lo stesso username}`, Error)
		}
	}
}
