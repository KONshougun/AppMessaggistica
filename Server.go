package main

import (
	"fmt"
	"log"
	"net"

	"github.com/KONshougun/AppMessaggistica/handlers"
	"github.com/joho/godotenv"
)

// ngrok http --domain=tops-actually-filly.ngrok-free.app 18854
const PORT = ":18854"

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Errore nel caricare .env:", err)
	}
}

func main() {
	loadEnv()

	ln, err := net.Listen("tcp", PORT)
	if err != nil {
		fmt.Printf("errore durante l'ascolto su %s: %v\n", PORT, err)
		return
	}
	defer ln.Close()

	fmt.Printf("server in ascolto su %s\n", PORT)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Printf("errore accettando la connessione: %v\n", err)
			continue
		}

		fmt.Printf("connessione da %s\n", conn.RemoteAddr())
		go func() {
			handleRequest(conn, 0)
		}()
	}
}

func handleRequest(conn net.Conn, id uint64) {
	defer conn.Close()

	connection := handlers.Conn{
		Conn: conn,
		Key:  nil,
		Iv:   [24]byte{0},
	}

	//	HANDSHAKE
	key, err := handlers.HandleHandshake(&connection)
	if err != nil {
		fmt.Println("Errore durante l'handshake")
		return
	}
	connection.Key = key

	//	LOG
	var userKey []byte
	for userKey == nil {
		password := ""
		action, msg, err := handlers.ReadHeader(&connection)
		if err != nil {
			fmt.Println("errore nella lettura dell'header")
			handlers.SendPacket(&connection, handlers.ERROR, false, []byte("Errore nella lettura della richiesta"))
			return
		}
		switch action {
		case handlers.SIGN_IN:
			id, password = handlers.SignIn(&connection, msg)
			if password == "" {
				fmt.Println("Errore nell'ottenimento della password")
			}
		case handlers.SIGN_UP:
			id, password = handlers.SignUp(&connection, msg)
			fmt.Printf("id: %v\n", id)
			fmt.Printf("password: %v\n", password)
			if password == "" {
				fmt.Println("Errore nell'ottenimento della password")
			}
		case handlers.END_SESSION:
			return;
		default:
			handlers.SendPacket(&connection, handlers.ERROR, false, []byte("Richiesta non valida"))
		}

		if password != "" {
			userKey = handlers.AuthenticateUser(id, password)
			if userKey == nil{
				fmt.Println("Errore nell'ottenimento della chiave")
			}
		}
	}

	//	RECORD
	for {
		action, msg, err := handlers.ReadHeader(&connection)
		if err != nil {
			fmt.Println("errore nella lettura dell'header")
			fmt.Printf("err: %v\n", err)
			handlers.SendPacket(&connection, handlers.ERROR, false, []byte("Errore nella lettura della richiesta"))
			return
		}
		fmt.Printf("action: %v\n", action)
		switch action {
		case handlers.CHECK_PASSWORD:
			handlers.CheckPassword(&connection, msg, id)
		case handlers.ADD_CONTACT:
			handlers.AddContact(&connection, msg, id, userKey)
		case handlers.GET_CONTACTS:
			handlers.GetContacts(&connection, msg, id, userKey)
		case handlers.SEND_MESSAGE:
			handlers.SendMessage(&connection, msg, id, userKey)
		case handlers.SET_BLOCK:
			handlers.SetBlockState(&connection, msg, id, userKey)
		case handlers.REMOVE_CONTACT:
			handlers.RemoveContact(&connection, msg, id, userKey)
		case handlers.SET_NICKNAME:
			handlers.SetNickname(&connection, msg, id, userKey)
		case handlers.END_SESSION:
			return
		default:
			handlers.SendPacket(&connection, handlers.ERROR, false, []byte("Richiesta non valida"))
		}
	}

}
