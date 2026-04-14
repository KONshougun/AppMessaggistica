package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	appcrypto "github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/handlers"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.org/x/crypto/hkdf"
)

func main() {
	conn, _ := net.Dial("tcp", "127.0.0.1:18854")
	defer conn.Close()

	key, err := handshake(conn)
	nonce := make([]byte, 24)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	//auth(conn, key, nonce, handlers.SIGN_IN, "Paolo", "pwd123456")
	auth(conn, key, nonce, handlers.SIGN_UP, "Giuseppe", "pwd123456")
	addContact(conn, key, nonce, handlers.ADD_CONTACT, "Paolo", "Paolino")
	for{
		time.Sleep(5 * time.Second)
	}
	//SendMsg(conn, handlers.END_SESSION, nil, nil)
}

const KYBER_PUB_KEY = "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"

func handshake(conn net.Conn) ([]byte, error) {
	scheme := kyber1024.Scheme()

	//Prendo la chiave pubblica
	pubBytes, err := base64.StdEncoding.DecodeString(KYBER_PUB_KEY)
	if err != nil {
		return nil, err
	}
	pk, err := scheme.UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}

	// invio al server il ct e il segreto
	ct, sharedSecret, err := scheme.Encapsulate(pk)
	if err != nil {
		return nil, err
	}
	SendMsg(conn, handlers.KYBER_INIT, nil, ct)

	//CONTROLLO CHE IL SERVER NON HA AVUTO PROBLEMI
	action, _, _, err := ReadFrame(conn)
	if action != handlers.KYBER_REPLY && err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, sharedSecret, nil, []byte("kyber-session")), key)
	return key, nil
}

func auth(conn net.Conn, key, nonce []byte, t byte, u, p string) {

	plain := []byte(u + ";" + p)
	nonce[0]++
	cipher, _ := appcrypto.EncodeChaCha20Poly1305(key, nonce, plain)

	SendMsg(conn, t, nonce, cipher)

	rt, payload, _, _ := ReadFrame(conn)
	fmt.Println("response:", rt, string(payload))
}

func addContact(conn net.Conn, key, nonce []byte, t byte, username, nickname string) {

	plain := []byte(username + ";" + nickname)
	nonce[0]++
	cipher, _ := appcrypto.EncodeChaCha20Poly1305(key, nonce, plain)

	SendMsg(conn, t, nonce, cipher)

	rt, payload, _, _ := ReadFrame(conn)
	fmt.Println("response:", rt, string(payload))
}

/*
action
length
nonce
error
*/
func ReadFrame(conn net.Conn) (byte, []byte, []byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, nil, err
	}

	action := header[0]
	length := binary.BigEndian.Uint16(header[1:3])
	hasNonce := header[3] == 1

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, nil, err
		}
	}

	var nonce []byte
	if hasNonce {
		nonce = make([]byte, 24)
		if _, err := io.ReadFull(conn, nonce); err != nil {
			return 0, nil, nil, err
		}
	}

	return action, payload, nonce, nil
}

func SendMsg(conn net.Conn, action byte, nonce []byte, msg []byte) {

	msgLen := uint16(len(msg))
	if msgLen > 60000 {
		fmt.Println("Messaggio troppo lungo")
		return
	}
	var buffer []byte
	if len(nonce) == 24 {
		buffer = make([]byte, 4+24+msgLen) // 4 header + msg + 24 nonce
		buffer[3] = 1
		copy(buffer[4+len(msg):], nonce[:])
	} else {
		buffer = make([]byte, 4+msgLen) // 4 header + msg
		buffer[3] = 0
	}
	buffer[0] = action
	binary.BigEndian.PutUint16(buffer[1:3], msgLen)
	if msgLen > 0 {
		copy(buffer[4:4+msgLen], msg)
	}

	if _, err := conn.Write(buffer); err != nil {
		fmt.Printf("Errore durante l'invio del messaggio: %v\n", err)
	}
}
