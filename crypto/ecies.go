package crypto

import (
	ecies "github.com/ecies/go"
)

func GetSharedSecret(privBytes, ct []byte) []byte {

	privKey := ecies.NewPrivateKeyFromBytes(privBytes)

	// decrypt = recupero shared secret
	sharedSecret, err := ecies.Decrypt(privKey, ct)
	if err != nil {
		return nil
	}
	return sharedSecret
}

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
		return nil, err
	}

	return ciphertext, nil
}

func DecodeECIES256(privKeyByte, ciphertext []byte) ([]byte, error) {
	privKey := ecies.NewPrivateKeyFromBytes(privKeyByte)

	decrypted, err := ecies.Decrypt(privKey, ciphertext)
	if err != nil {
		panic(err)
	}

	return decrypted, nil
}
