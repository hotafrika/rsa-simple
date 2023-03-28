package crypter

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/pkg/errors"
)

// Encrypt encrypts the given message with RSA-OAEP.
func Encrypt(publicKey *rsa.PublicKey, message []byte, label []byte) ([]byte, error) {
	rng := rand.Reader
	b, err := rsa.EncryptOAEP(sha256.New(), rng, publicKey, message, label)
	if err != nil {
		return nil, errors.Wrap(err, "encrypt with EncryptOAEP()")
	}
	return b, nil
}

// EncryptB64 encrypts the given message with RSA-OAEP and returns Base64 of the cipher.
func EncryptB64(publicKey *rsa.PublicKey, message []byte, label []byte) (string, error) {
	cipher, err := Encrypt(publicKey, message, label)
	if err != nil {
		return "", errors.Wrap(err, "encrypt with Encrypt()")
	}
	cipherB64 := base64.StdEncoding.EncodeToString(cipher)
	return cipherB64, nil
}

// EncryptHEX encrypts the given message with RSA-OAEP and returns HEX of the cipher.
func EncryptHEX(publicKey *rsa.PublicKey, message []byte, label []byte) (string, error) {
	cipher, err := Encrypt(publicKey, message, label)
	if err != nil {
		return "", errors.Wrap(err, "encrypt with Encrypt()")
	}
	cipherHEX := hex.EncodeToString(cipher)
	return cipherHEX, nil
}

// Decrypt decrypts cipher ([]byte) using RSA-OAEP.
func Decrypt(privateKey *rsa.PrivateKey, cipher []byte, label []byte) ([]byte, error) {
	b, err := rsa.DecryptOAEP(sha256.New(), nil, privateKey, cipher, label)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt with DecryptOAEP()")
	}
	return b, nil
}

// DecryptB64 decrypts cipher (in Base64 string) using RSA-OAEP.
func DecryptB64(privateKey *rsa.PrivateKey, cipherB64 string, label []byte) ([]byte, error) {
	cipher, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return nil, errors.Wrap(err, "decode from base64 DecodeString")
	}
	return Decrypt(privateKey, cipher, label)
}

// DecryptHEX decrypts cipher (in HEX string) using RSA-OAEP.
func DecryptHEX(privateKey *rsa.PrivateKey, cipherHEX string, label []byte) ([]byte, error) {
	cipher, err := hex.DecodeString(cipherHEX)
	if err != nil {
		return nil, errors.Wrap(err, "decode from base64 DecodeString")
	}
	return Decrypt(privateKey, cipher, label)
}
