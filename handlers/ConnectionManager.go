package handlers

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/KONshougun/AppMessaggistica/crypto"
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
	SUCCESS byte = iota
	ERROR
	END_SESSION
	SESSION_INIT

	//Load Data
	LOAD_START
	PROGRESS
	LOAD_END

	//User
	SIGN_IN
	SIGN_UP
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
	GET_CHATS
	SEND_MESSAGE
	CLEAR_CHAT
	DELETE_USER

	//Other
	RESET_KEY
)

type Conn struct {
	Conn net.Conn
	Key  []byte
	Iv   [24]byte
}

func HandleHandshake(conn *Conn) ([]byte, error) {

	action, clientPubBytes, err := ReadHeader(conn)
	if err != nil || action != SESSION_INIT {
		SendPacket(conn, ERROR, false, []byte("Handshake error"))
		return nil, err
	}

	privBytes := getEnvPrivKey()
	if privBytes == nil {
		SendPacket(conn, ERROR, false, []byte("Missing server key"))
		return nil, fmt.Errorf("missing key")
	}

	curve := ecdh.X25519()

	serverPriv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Invalid private key"))
		return nil, err
	}

	clientPub, err := curve.NewPublicKey([]byte(clientPubBytes))
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("Invalid client public key"))
		return nil, err
	}

	// shared secret (Diffie-Hellman)
	sharedSecret, err := serverPriv.ECDH(clientPub)
	if err != nil {
		SendPacket(conn, ERROR, false, []byte("ECDH failed"))
		return nil, err
	}

	// derive session key
	key := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, sharedSecret, nil, []byte("session")), key)

	return key, nil
}

/*
action
text
error
*/
func ReadHeader(conn *Conn) (byte, string, error) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(conn.Conn, header); err != nil {
		return 0, "", err
	}
	if !bytes.Equal(header[0:3], []byte("kon")) {
		return 0, "", fmt.Errorf("Errore messaggio ricevuto non valido")
	}

	action := header[3]

	raw := binary.BigEndian.Uint16(header[4:6])
	hasNonce := (raw & 0x8000) != 0
	length := raw & 0x7FFF

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
		msg, err := crypto.DecryptXChaCha20Poly1305(conn.Key, nonce, text)
		if err != nil {
			SendPacket(conn, ERROR, false, []byte("Errore nel decifrare il messaggio"))
			return 0, "", fmt.Errorf("Errore nel decifrare il messaggio")
		}
		conn.Iv[0]++
		return action, string(msg), nil
	}

	return action, string(text), nil
}
func SendPacket(conn *Conn, action byte, hasNonce bool, msg []byte) error {
	salt := "kon"
	msgLen := uint16(len(msg))

	if msgLen > 10000 {
		return fmt.Errorf("Messaggio troppo lungo")
	}

	var buffer []byte
	if hasNonce {
		if conn.Iv[0] == 255 {
			resetKey(conn)
			return fmt.Errorf("Chiave di sessione scaduta")
		}
		conn.Iv[0]++

		buffer = make([]byte, 6+24+16+msgLen) // 6 header + msg + 24 nonce + 16 MAC

		msg, err := crypto.EncryptXChaCha20Poly1305(conn.Key, conn.Iv[:], msg)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(buffer[4:6], msgLen+16)
		buffer[4] |= 0x80
		copy(buffer[6:6+msgLen+16], msg)

		copy(buffer[6+msgLen+16:], conn.Iv[:])
	} else {
		buffer = make([]byte, 6+msgLen) // 6 header + msg
		binary.BigEndian.PutUint16(buffer[4:6], msgLen)
		copy(buffer[6:6+msgLen], msg)
	}
	copy(buffer[0:3], []byte(salt))
	buffer[3] = action

	if _, err := conn.Conn.Write(buffer); err != nil {
		fmt.Printf("Errore durante l'invio del messaggio: %v\n", err)
	}
	return nil
}

func resetKey(conn *Conn) {

}
