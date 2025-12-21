package main

import (
	"fmt"
	"log"
	"net/http"
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

const (
	Username        string = "Username"
	ID              string = "ID"
	Password        string = "Password"
	ContactUsername string = "ContactUsername"
	Contacts        string = "Contacts"
	Nickname        string = "Nickname"
	Text            string = "Text"
	Error           string = "Error"
)

func main() {
	http.HandleFunc("/"+SignIn, signIn)
	http.HandleFunc("/"+LogIn, logIn)
	http.HandleFunc("/"+CheckPassword, checkPassword)
	http.HandleFunc("/"+SetPassword, setPassword)
	http.HandleFunc("/"+AddContact, addContact)
	http.HandleFunc("/"+SetNickname, setNickname)
	http.HandleFunc("/"+GetContacts, getContacts)
	http.HandleFunc("/"+AddGroup, addGroup)
	http.HandleFunc("/"+GetChats, getChats)
	http.HandleFunc("/"+SendMessage, sendMessage)
	http.HandleFunc("/"+RemoveMessage, removeMessage)
	http.HandleFunc("/"+ClearChat, clearChat)
	http.HandleFunc("/"+RemoveContact, removeContact)
	http.HandleFunc("/"+BlockContact, blockContact)
	http.HandleFunc("/"+UnlockContact, unlockContact)
	http.HandleFunc("/"+RemoveUser, removeUser)

	fmt.Println("Server HTTPS in ascolto sulla porta " + PORT)
	err := http.ListenAndServe(PORT, nil)

	if err != nil {
		log.Fatal("Errore server HTTPS:", err)
	}
}
