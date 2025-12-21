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
		http.Error(w, "Metodo non consentito", http.StatusMethodNotAllowed)
		return
	}

	// Parse dei dati form-urlencoded
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Errore nel parsing del form", http.StatusBadRequest)
		return
	}

	var username string = r.PostForm.Get(Username)
	var password string = r.PostForm.Get(Password)

	if len(username) < 3 || len(username) > 25 ||
		len(password) < 8 || len(password) > 50 {
		http.Error(w, "Username o password non validi", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	db, err := databaseConnection.StartConnection()
	if err != nil {
		http.Error(w, "Errore connessione al database", http.StatusInternalServerError)
	}
	defer db.Close()

	query := "SELECT id FROM users WHERE username = ?;"
	rows, err := db.Query(query, username)
	if err != nil {
		http.Error(w, "Errore richiesta al database", http.StatusInternalServerError)
	}
	defer rows.Close()
	if rows.Next() {
		http.Error(w, "Username già esistente", http.StatusConflict)
		return
	}

	// CREO L'UTENTE
	passwordHash, err := crypto.HashPassword([]byte(password))
	if err != nil {
		http.Error(w, "Errore nell'hashing della password", http.StatusInternalServerError)
		return
	}
	privKey, pubKey, err := crypto.GenerateKeysECIES256()
	if err != nil {
		http.Error(w, "Errore nella generazione delle chiavi", http.StatusInternalServerError)
		return
	}
	query = "INSERT INTO users (username, password_hash, public_key) VALUES (?,?,?);"
	_, err = db.Exec(query, username, passwordHash, pubKey)
	if err != nil {
		http.Error(w, "Errore nell'inserimento dell'utente nel database", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, `{"%s":"%s","%s":"%x"}`, Username, username, PrivateKey, privKey)
}

/*
func LogIn(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LogIn")

	// Assicurati che sia una POST
	if r.Method != http.MethodPost {
		http.Error(w, "Metodo non consentito", http.StatusMethodNotAllowed)
		return
	}

	// Parse dei dati form-urlencoded
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Errore nel parsing del form", http.StatusBadRequest)
		return
	}
}
*/
