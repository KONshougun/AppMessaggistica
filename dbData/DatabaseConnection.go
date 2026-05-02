package dbData

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

// USERS
const (
	Users        = "users"
	Username     = "username"
	LastLog      = "last_log"
	PwdHash      = "pwd_hash"
	PwdSalt      = "pwd_salt"
	CipherMk     = "cipher_mk"
	MkNonce      = "mk_nonce"
	FailedLogins = "failed_logins"
)

// CONTACTS
const (
	Contacts        = "contacts"
	UsernameHash    = "username_hash"
	UsernameContact = "username_contact"
	UsernameNonce   = "username_nonce"
	Nickname        = "nickname"
	NicknameNonce   = "nickname_nonce"
	PubKey          = "pub_key"
	IsBlocked       = "is_blocked"
)

// MEMBERS_CHAT
const (
	MembersChat   = "members_chat"
	IdMsgBgn      = "id_msg_bgn"
	ChatKey       = "chat_key"
	ChatKeyNonce  = "chat_key_nonce"
	LastMsgReadId = "last_msg_read_id"
)

// CHATS
const (
	Chats   = "chats"
	Name    = "name"
	Counter = "counter"
)

// MESSAGES
const (
	Messages = "messages"
	IdSender = "id_sender"
	Message  = "message"
	SendTime = "send_time"
)

// REMOVED MESSAGES
const (
	RemovedMessages = "removed_messages"
	IdMsg           = "id_msg"
	IdMsgNonce      = "id_msg_nonce"
)

// NONCE LOGS
const (
	UsersNoncesLogs = "users_nonces_logs"
	ChatsNoncesLogs = "chats_nonces_logs"
	Nonce           = "nonce"
)

// ERRORS LOGS
const (
	ErrorsLogs = "errors_logs"
	Log        = "log"
)

// GENERAL
const (
	Id          = "id"
	IdUser      = "id_user"
	IdChat      = "id_chat"
	IdChatNonce = "id_chat_nonce"
	Flag        = "flag"
)

func StartConnection() (*sql.DB, error) {

	DBUser := string(os.Getenv("DB_USER"))
	DBPassword := string(os.Getenv("DB_PASSWORD"))
	DBHost := string(os.Getenv("DB_HOST"))
	DBPort := string(os.Getenv("DB_PORT"))
	DBName := string(os.Getenv("DB_NAME"))

	dsn := DBUser + ":" + DBPassword + "@tcp(" + DBHost + ":" + DBPort + ")/" + DBName

	// Apriamo la connessione
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	// Test connessione
	if err = db.Ping(); err != nil {
		fmt.Println(err)
		return nil, err
	}
	return db, nil
}

type QueryRower interface {
	QueryRow(query string, args ...interface{}) *sql.Row
}

func NewUserNonce(qr QueryRower, idUser int64) []byte {
	query := fmt.Sprintf(`
		WITH valore AS (
			SELECT ? AS id, ? AS newNonce
		)
		SELECT 1
		WHERE EXISTS (
			SELECT 1
			FROM %s, valore
			WHERE %s = valore.id AND (%s = valore.newNonce OR %s = valore.newNonce)
			UNION
			SELECT 1
			FROM %s, valore
			WHERE %s = valore.id AND %s = valore.newNonce
			UNION
			SELECT 1
			FROM %s, valore
			WHERE %s = valore.id AND (%s = valore.newNonce OR %s = valore.newNonce)
			UNION
			SELECT 1
			FROM %s, valore
			WHERE %s = valore.id AND %s = valore.newNonce
		);
	`, Contacts, IdUser, UsernameNonce, NicknameNonce,
		MembersChat, IdUser, ChatKeyNonce,
		RemovedMessages, IdUser, IdMsgNonce, IdChatNonce,
		UsersNoncesLogs, IdUser, Nonce)
	for {
		nonce := make([]byte, 24)
		if _, err := rand.Read(nonce); err != nil {
			fmt.Printf("err: %v\n", err)
			return nil
		}

		var found bool
		if err := qr.QueryRow(query, idUser, nonce).Scan(&found); err == sql.ErrNoRows {
			return nonce
		} else {
			fmt.Printf("err: %v\n", err)
			return nil
		}
	}
}
func NewChatNonce(qr QueryRower, idChat int64) ([]byte, error) {

	//	------------------- DA FARE ---------------------------
	query := fmt.Sprintf(`
		WITH valore AS (
			SELECT ? AS id, ? AS newNonce
		)
		SELECT 1
		WHERE EXISTS (
			SELECT 1
			FROM %s, valore
			WHERE %s = valore.id AND (%s = valore.newNonce OR %s = valore.newNonce)
			UNION
			SELECT 1
			FROM %s, valore
			WHERE %s = valore.id AND (%s = valore.newNonce OR %s = valore.newNonce)
			UNION
			SELECT 1
			FROM %s, valore
			WHERE %s = valore.id AND (%s = valore.newNonce OR %s = valore.newNonce)
			UNION
			SELECT 1
			FROM %s, valore
			WHERE %s = valore.id %s = valore.newNonce
		);
	`, Contacts, IdUser, UsernameNonce, NicknameNonce, MembersChat, IdUser, IdChatNonce, ChatKeyNonce,
		RemovedMessages, IdUser, IdMsgNonce, IdChatNonce,
		UsersNoncesLogs, IdUser, Nonce)
	for {
		nonce := make([]byte, 24)
		_, err := rand.Read(nonce)
		if err != nil {
			return nil, err
		}

		var found bool
		err = qr.QueryRow(query, idChat, nonce).Scan(&found)
		if err == sql.ErrNoRows {
			return nonce, nil
		} else if err != nil {
			return nil, err
		}
	}
}
