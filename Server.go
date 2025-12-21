package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/KONshougun/AppMessaggistica/httpRequest"
)

// ngrok http --domain=tops-actually-filly.ngrok-free.app 18854
const PORT = ":18854"

const (
	SignIn        string = "SignIn"
	LogIn         string = "LogIn"
	CheckPassword string = "CheckPassword"
	SetPassword   string = "SetPassword"
	RemoveUser    string = "RemoveUser"

	AddContact    string = "AddContact"
	RemoveContact string = "RemoveContact"
	BlockContact  string = "BlockContact"
	UnlockContact string = "UnlockContact"
	SetNickname   string = "SetNickname"
	AddGroup      string = "AddGroup"
	GetContacts   string = "GetContacts"

	SendMessage   string = "SendMessage"
	GetChats      string = "GetChats"
	ClearChat     string = "ClearChat"
	RemoveMessage string = "RemoveMessage"
)

func main() {
	http.HandleFunc("/"+SignIn, httpRequest.SignIn)

	fmt.Println("Server HTTPS in ascolto sulla porta " + PORT)
	err := http.ListenAndServe(PORT, nil)

	if err != nil {
		log.Fatal("Errore server HTTPS:", err)
	}
}
	/*http.HandleFunc("/"+LogIn, httpRequest.LogIn)
	http.HandleFunc("/"+CheckPassword, signIn)
	http.HandleFunc("/"+SetPassword, signIn)
	http.HandleFunc("/"+AddContact, signIn)
	http.HandleFunc("/"+SetNickname, signIn)
	http.HandleFunc("/"+GetContacts, signIn)
	http.HandleFunc("/"+AddGroup, signIn)
	http.HandleFunc("/"+GetChats, signIn)
	http.HandleFunc("/"+SendMessage, signIn)
	http.HandleFunc("/"+RemoveMessage, signIn)
	http.HandleFunc("/"+ClearChat, signIn)
	http.HandleFunc("/"+RemoveContact, signIn)
	http.HandleFunc("/"+BlockContact, signIn)
	http.HandleFunc("/"+UnlockContact, signIn)
	http.HandleFunc("/"+RemoveUser, signIn)*/