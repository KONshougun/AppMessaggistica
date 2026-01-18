package httpRequest

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/KONshougun/AppMessaggistica/crypto"
	"github.com/KONshougun/AppMessaggistica/dbData"
)

// SE UN UTENTE PERDA LA MK PIù DI UNA VOLTA, BISOGNA RIGENERARE LA RECOVERY KEY
// (E LE RECOVERY_MK DEL DB)

func RecoveryKey(id uint64, db *sql.DB) ([]byte, error) {
	recoveryKey := []byte(os.Getenv("RECOVERY_KEY"))

	if len(recoveryKey) != 32 {
		return nil, fmt.Errorf("recovery key non impostata nel server")
	}

	var recoveryMk []byte
	var nonce []byte
	query := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s = ?", dbData.RecoveryMk, dbData.ChatKeyNonce, dbData.Users, dbData.Id)
	err := db.QueryRow(query, id).Scan(&recoveryMk, &nonce)
	if err != nil {
		return nil, err
	}
	decipherMk, err := crypto.DecodeAES(recoveryKey, nonce, recoveryMk)
	if err != nil {
		return nil, err
	}
	return decipherMk, nil
}
