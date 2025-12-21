package crypto

import (
	"fmt"

	ecies "github.com/ecies/go"
)

// privKey = 32B
// pubKey = 33B (compressa)
func GenerateKeysECIES256() ([]byte, []byte, error) {

	privKey, err := ecies.GenerateKey()
	if err != nil {
		panic(err)
	}
	pubKey := privKey.PublicKey

	return privKey.Bytes(), pubKey.Bytes(true), nil
}

func EncodeECIES256(pubKeyByte, plaintext []byte) ([]byte, error) {

	pubKey, err := ecies.NewPublicKeyFromBytes(pubKeyByte)

	if err != nil {
		return nil, err
	}

	// Cifratura con la chiave pubblica
	ciphertext, err := ecies.Encrypt(pubKey, plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	return ciphertext, nil
}

func DecodeECIES256(privKeyByte, ciphertext []byte) ([]byte, error) {
	privKey := ecies.NewPrivateKeyFromBytes(privKeyByte)

	decrypted, err := ecies.Decrypt(privKey, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted: %s\n", decrypted)

	return decrypted, nil
}
