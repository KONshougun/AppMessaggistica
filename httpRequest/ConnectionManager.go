package httpRequest

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/KONshougun/AppMessaggistica/databaseConnection"
)

const (
	Username        string = "Username"
	ID              string = "ID"
	Password        string = "Password"
	PrivateKey      string = "PrivateKey"
	ContactUsername string = "ContactUsername"
	Nickname        string = "Nickname"
	Contacts        string = "Contacts"
	Text            string = "Text"
	Success         string = "Success"
	Error           string = "Error"
)

func InitConnections(w http.ResponseWriter, r *http.Request) (*sql.DB, error) {
	w.Header().Set("Content-Type", "application/json")
	if !checkConnection(r) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return nil, fmt.Errorf("connection check failed")
	}
	db, err := databaseConnection.StartConnection()
	if err != nil {
		fmt.Fprintf(w, `{"%s": connessione al database}`, Error)
		return nil, err
	}
	return db, nil
}

func checkConnection(r *http.Request) bool {
	// Assicurati che sia una POST
	if r.Method != http.MethodPost {
		return false
	}

	// Parse dei dati form-urlencoded
	err := r.ParseForm()
	if err != nil {
		return false
	}
	return true
}
