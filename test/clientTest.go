package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/KONshougun/AppMessaggistica/crypto"
	appcrypto "github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/handlers"
	"golang.org/x/crypto/hkdf"
)

func main() {
	conn, _ := net.Dial("tcp", "127.0.0.1:18854")
	defer conn.Close()
	iv[0]++

	key, err := handshake(conn)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}

	//auth(conn, key, handlers.SIGN_IN, "Giuseppe", "pwd123456")
	auth(conn, key, handlers.SIGN_UP, "Giuseppe", "pwd123456")

	getContacts(conn, key)
	//sendMessage(conn, key, handlers.SEND_MESSAGE, 4, "Ciao Paolo!!")
	getChats(conn, key)

	fmt.Println("-------------------- FINITO -------------------------")
	SendPacket(conn, handlers.END_SESSION, nil, nil)
}

const X25519_PUBLIC_KEY = "8sUS0/lbCW+ksvhgk3gWmBFQNA8Fp+jKzXHFkIPBl2I="

var privKey = []byte{91, 49, 52, 49, 32, 49, 49, 49, 32, 49, 55, 48, 32, 49, 53, 54, 32, 49, 48, 57, 32, 49, 56, 56, 32, 50, 48, 53, 32, 49, 55, 56, 32, 55, 57, 32, 55, 48, 32, 55, 51, 32, 52, 49, 32, 49, 48, 48, 32, 49, 48, 51, 32, 49, 56, 51, 32, 49, 55, 53, 32, 50, 53, 48, 32, 49, 48, 51, 32, 51, 54, 32, 49, 51, 57, 32, 57, 55, 32, 49, 57, 53, 32, 49, 48, 49, 32, 49, 49, 32, 49, 52, 51, 32, 57, 49, 32, 49, 52, 57, 32, 49, 57, 48, 32, 49, 56, 32, 49, 51, 51, 32, 55, 52, 32, 49, 56, 52, 93}
var id int64 = 38
var iv []byte = make([]byte, 24)

func handshake(conn net.Conn) ([]byte, error) {

	curve := ecdh.X25519()

	// generate ephemeral keypair
	clientPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	clientPub := clientPriv.PublicKey()

	// send client public key
	SendPacket(conn, handlers.SESSION_INIT, nil, clientPub.Bytes())

	serverKey, err := base64.StdEncoding.DecodeString(X25519_PUBLIC_KEY)
	if err != nil {
		return nil, err
	}
	serverPub, err := curve.NewPublicKey(serverKey)
	if err != nil {
		return nil, err
	}

	// shared secret (Diffie-Hellman)
	sharedSecret, err := clientPriv.ECDH(serverPub)
	if err != nil {
		return nil, err
	}

	// derive session key
	key := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, sharedSecret, nil, []byte("session")), key)

	return key, nil
}

func auth(conn net.Conn, key []byte, t byte, u, p string) {

	plain := []byte(u + ";" + p)
	cipher, _ := appcrypto.EncryptXChaCha20Poly1305(key, iv, plain)
	SendPacket(conn, t, iv, cipher)

	rt, _ /*payload*/, err := ReadHeader(conn, key)
	if err == nil && rt == handlers.SUCCESS {
		/*params := strings.Split(payload, ";")
		if len(params) != 2 {
			fmt.Println("invalid auth response payload")
			SendPacket(conn, handlers.ERROR, nil, nil)
			return
		}
		parsedID, err := strconv.ParseUint(params[0], 10, 64)
		if err != nil {
			fmt.Printf("invalid id in auth response: %v\n", err)
			SendPacket(conn, handlers.ERROR, nil, nil)
			return
		}
		id = int64(parsedID)
		privKey = []byte(params[1])
		*/
	} else {
		return
	}
}

func addContact(conn net.Conn, key []byte, t byte, username, nickname string) {

	plain := []byte(username + ";" + nickname)

	cipher, _ := appcrypto.EncryptXChaCha20Poly1305(key, iv, plain)

	SendPacket(conn, t, iv, cipher)

	rt, payload, _ := ReadHeader(conn, key)
	fmt.Println("response:", rt, string(payload))
}

func getContacts(conn net.Conn, key []byte) {

	SendPacket(conn, handlers.GET_CONTACTS, nil, nil)

	response, payload, err := ReadHeader(conn, key)
	if err != nil || response != handlers.LOAD_START {
		fmt.Printf("err: %v\n", err)
		fmt.Printf("response: %v\n", response)
		return
	}

	for true {
		response, payload, err = ReadHeader(conn, key)
		if err != nil {
			fmt.Printf("err: %v\n", err)
			return
		} else if response == handlers.PROGRESS {
			fmt.Printf("payload: %v\n", payload)
		} else if response == handlers.LOAD_END {
			fmt.Println("contatti finiti")
			break
		} else {
			fmt.Println("Anomalia get contact")
			fmt.Printf("response: %v\n", response)
			fmt.Printf("payload: %v\n", payload)
		}
	}
}

func sendMessage(conn net.Conn, key []byte, t byte, chatId int64, msg string) {

	plain := []byte(fmt.Sprint(chatId) + ";" + msg)

	cipher, err := appcrypto.EncryptXChaCha20Poly1305(key, iv, plain)
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}

	SendPacket(conn, t, iv, cipher)

	rt, payload, _ := ReadHeader(conn, key)
	fmt.Println("response:", rt, string(payload))
}
func getChats(conn net.Conn, key []byte) {

	SendPacket(conn, handlers.GET_CHATS, nil, nil)

	response, payload, err := ReadHeader(conn, key)
	if err != nil || response != handlers.LOAD_START {
		fmt.Printf("err: %v\n", err)
		fmt.Printf("response: %v\n", response)
		return
	}

	for true {
		response, payload, err = ReadHeader(conn, key)
		if err != nil {
			fmt.Printf("err: %v\n", err)
			return
		} else if response == handlers.PROGRESS {
			fmt.Printf("payload: %v\n", payload)
		} else if response == handlers.LOAD_END {
			fmt.Println("contatti finiti")
			break
		} else if response == handlers.ERROR {
			fmt.Printf("response: %v\n", response)
			fmt.Printf("payload: %v\n", payload)
			return
		} else {
			fmt.Println("Anomalia get chats")
			fmt.Printf("response: %v\n", response)
			fmt.Printf("payload: %v\n", payload)
			return
		}
	}
}

/*
action
text
error
*/
func ReadHeader(conn net.Conn, key []byte) (byte, string, error) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", err
	}
	if !bytes.Equal(header[0:3], []byte("kon")) {
		return 0, "", fmt.Errorf("Errore messaggio ricevuto non valido")
	}

	action := header[3]
	length := binary.BigEndian.Uint16(header[4:6]) & 0x7FFF
	hasNonce := header[4]&0x80 != 0

	if length == 0 {
		return action, "", nil
	} else if length > 60000 {
		return 0, "", fmt.Errorf("lunghezza del messaggio troppo grande: %d", length)
	}

	buffer := make([]byte, length)
	if hasNonce {
		buffer = make([]byte, length+24)
	}

	if _, err := io.ReadFull(conn, buffer); err != nil {
		return 0, "", err
	}

	text := buffer[:length]
	var nonce []byte = nil
	if hasNonce {
		nonce = buffer[length:]
		if len(nonce) != 24 {
			//forse andrebbe fatto un resetKey
			//resetKey(conn)
			return 0, "", fmt.Errorf("nonce non valido")
		}
		msg, err := crypto.DecryptXChaCha20Poly1305(key, nonce, text)
		if err != nil {
			fmt.Printf("err: %v\n", err)
			SendPacket(conn, handlers.ERROR, nil, []byte("Errore nel decifrare il messaggio"))
			return 0, "", fmt.Errorf("Errore nel decifrare il messaggio")
		}

		iv[0] = nonce[0] + 1
		return action, string(msg), nil
	}

	return action, string(text), nil
}

func SendPacket(conn net.Conn, action byte, nonce []byte, msg []byte) bool {
	salt := "kon"
	msgLen := uint16(len(msg))

	if msgLen > 10000 {
		fmt.Println("Messaggio troppo lungo")
		return false
	}

	var buffer []byte
	if len(nonce) == 24 {

		buffer = make([]byte, 6+24+msgLen) // 6 header + msg + 24 nonce

		binary.BigEndian.PutUint16(buffer[4:6], msgLen)
		buffer[4] |= 0x80
		copy(buffer[6+msgLen:], nonce)
		copy(buffer[6:6+msgLen], msg)
		iv[0]++

	} else {
		buffer = make([]byte, 6+msgLen) // 6 header + msg
		binary.BigEndian.PutUint16(buffer[4:6], msgLen)
		copy(buffer[6:6+msgLen], msg)
	}
	copy(buffer[0:3], []byte(salt))
	buffer[3] = action

	if _, err := conn.Write(buffer); err != nil {
		fmt.Printf("Errore durante l'invio del messaggio: %v\n", err)
	}
	return true
}
