package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/KONshougun/AppMessaggistica/httpRequest"
	"github.com/joho/godotenv"
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
	SetBlockState string = "SetBlockState"
	SetNickname   string = "SetNickname"
	AddGroup      string = "AddGroup"
	GetContacts   string = "GetContacts"

	SendMessage string = "SendMessage"
	GetChats    string = "GetChats"
	ClearChat   string = "ClearChat"
	DeleteUser  string = "DeleteUser"
)

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Errore nel caricare .env:", err)
	}
}

func main() {
	loadEnv()

	http.HandleFunc("/"+SignIn, httpRequest.SignIn)
	http.HandleFunc("/"+LogIn, httpRequest.LogIn)
	http.HandleFunc("/"+CheckPassword, httpRequest.CheckPassword)
	http.HandleFunc("/"+AddContact, httpRequest.AddContact)
	http.HandleFunc("/"+GetContacts, httpRequest.GetContacts)
	http.HandleFunc("/"+SetBlockState, httpRequest.SetBlockState)
	http.HandleFunc("/"+SetNickname, httpRequest.SetNickname)
	http.HandleFunc("/"+RemoveContact, httpRequest.RemoveContact)
	http.HandleFunc("/"+SendMessage, httpRequest.SendMessage)

	fmt.Println("Server HTTPS in ascolto sulla porta " + PORT)
	err := http.ListenAndServe(PORT, nil)

	if err != nil {
		log.Fatal("Errore server HTTPS:", err)
	}
}

/*
	http.HandleFunc("/"+AddGroup, signIn)
	http.HandleFunc("/"+GetChats, signIn)
	http.HandleFunc("/"+ClearChat, signIn)
	http.HandleFunc("/"+RemoveMessage, signIn)

	http.HandleFunc("/"+DeleteUser, signIn)
	http.HandleFunc("/"+SetPassword, signIn)
*/
