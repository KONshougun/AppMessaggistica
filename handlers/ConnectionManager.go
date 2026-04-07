package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.org/x/crypto/hkdf"
)

/*const (
	Id              string = "Id"
	Username        string = "Username"
	Password        string = "Password"
	PrivateKey      string = "PrivateKey"
	ContactUsername string = "ContactUsername"
	BlockState      string = "BlockState"
	Nickname        string = "Nickname"
	Contacts        string = "Contacts"
	ChatId          string = "ChatId"
	Message         string = "Message"
	Success         string = "Success"
	Error           string = "Error"
)*/

const (
	//Handshsake
	KYBER_INIT byte = iota
	KYBER_REPLY

	//User
	SIGN_IN
	SIGN_UP
	SIGN_RESPONSE
	CHECK_PASSWORD
	SET_PASSWORD
	REMOVE_ACCOUNT

	//Contact
	ADD_CONTACT
	REMOVE_CONTACT
	SET_BLOCK
	SET_NICKNAME
	ADD_GROUP
	GET_CONTACTS

	//Chats
	SEND_MESSAGE
	CLEAR_CHAT
	DELETE_USER

	//GET CHATS
	GET_CHATS_START
	GET_CHATS_PROGRESS
	GET_CHATS_END


	//Other
	RESET_KEY
	SUCCESS
	ERROR
	END_SESSION
)

type Conn struct {
	Conn net.Conn
	Key  []byte
	Iv   [24]byte
}

func HandleHandshake(conn *Conn) ([]byte, error) {
	action, ct, err := ReadHeader(conn)
	if err != nil || action != KYBER_INIT || len(ct) != kyber1024.CiphertextSize {
		SendPacket(conn, ERROR, false, []byte("Errore nella richiesta di handshake"))
		fmt.Printf("err: %v\n", err)
		return nil, err
	}

	//Riprendo la private key
	pkBase64 := os.Getenv("KYBER_PRIV_KEY")
	if pkBase64 == "" {
		fmt.Printf("pkBase64: %v\n", pkBase64)
		SendPacket(conn, ERROR, false, []byte("KYBER_PRIV_KEY non impostata"))
		return nil, err
	}
	pkBytes, err := base64.StdEncoding.DecodeString(pkBase64)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		SendPacket(conn, ERROR, false, []byte("Base64 non valida"))
		return nil, err
	}

	//Recupero la chiave
	scheme := kyber1024.Scheme()
	sk, err := scheme.UnmarshalBinaryPrivateKey(pkBytes)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		SendPacket(conn, ERROR, false, []byte("Private key non valida"))
		return nil, err
	}

	// Decapsulate
	sharedSecret, err := scheme.Decapsulate(sk, []byte(ct))
	if err != nil {
		fmt.Printf("err: %v\n", err)
		SendPacket(conn, ERROR, false, []byte("Errore nel decapsulate"))
		return nil, err
	}

	// Deriva chiave simmetrica
	key := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, sharedSecret, nil, []byte("kyber-session")), key)

	// Conferma handshake al client
	SendPacket(conn, KYBER_REPLY, false, nil)
	return key, nil
}

/*
action
text
error
*/
func ReadHeader(conn *Conn) (byte, string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn.Conn, header); err != nil {
		return 0, "", err
	}
	action := header[0]
	length := binary.BigEndian.Uint16(header[1:3])
	hasNonce := header[3] == 1

	if length == 0 {
		return action, "", nil
	} else if length > 60000 {
		return 0, "", fmt.Errorf("lunghezza del messaggio troppo grande: %d", length)
	}

	buffer := make([]byte, length)
	if hasNonce {
		buffer = make([]byte, length+24)
	}

	if _, err := io.ReadFull(conn.Conn, buffer); err != nil {
		return 0, "", err
	}

	text := buffer[:length]
	var nonce []byte = nil
	if hasNonce {
		nonce = buffer[length : length+24]
		if len(nonce) != 24 || nonce[0] != conn.Iv[0]+1 {
			//forse andrebbe fatto un resetKey
			//resetKey(conn)
			return 0, "", fmt.Errorf("nonce non valido")
		}
		msg, err := crypto.DecodeChaCha20Poly1305(conn.Key, nonce, text)
		if err != nil {
			SendPacket(conn, ERROR, false, []byte("Errore nel decifrare il messaggio"))
			return 0, "", fmt.Errorf("Errore nel decifrare il messaggio")
		}
		conn.Iv[0]++
		return action, string(msg), nil
	}

	return action, string(text), nil
}

func SendPacket(conn *Conn, action byte, hasNonce bool, msg []byte) bool {
	msgLen := uint16(len(msg))

	if msgLen > 60000 {
		fmt.Println("Messaggio troppo lungo")
		return false
	}

	var buffer []byte
	if hasNonce {
		if conn.Iv[0] == 255 {
			fmt.Println("Chiave di sessione scaduta")
			resetKey(conn)
			return false
		}
		conn.Iv[0]++

		buffer = make([]byte, 4+24+msgLen) // 4 header + msg + 24 nonce
		buffer[3] = 1
		copy(buffer[4+msgLen:], conn.Iv[:])
	} else {
		buffer = make([]byte, 4+msgLen) // 4 header + msg
		buffer[3] = 0
	}
	buffer[0] = action
	binary.BigEndian.PutUint16(buffer[1:3], msgLen)
	copy(buffer[4:4+msgLen], msg)

	_, err := conn.Conn.Write(buffer)
	if err != nil {
		fmt.Printf("Errore durante l'invio del messaggio: %v\n", err)
	}
	return true
}

func resetKey(conn *Conn) {

}