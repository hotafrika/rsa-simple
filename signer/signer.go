package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/pkg/errors"
)

func GetSignature(privateKey *rsa.PrivateKey, message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, errors.Wrap(err, "get signature SignPKCS1v15")
	}
	return signature, nil
}

func GetSignatureB64(privateKey *rsa.PrivateKey, message []byte) (string, error) {
	signature, err := GetSignature(privateKey, message)
	if err != nil {
		return "", errors.Wrap(err, "get signature GetSignature")
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	return signatureBase64, nil
}

func GetSignatureHEX(privateKey *rsa.PrivateKey, message []byte) (string, error) {
	signature, err := GetSignature(privateKey, message)
	if err != nil {
		return "", errors.Wrap(err, "get signature GetSignature")
	}
	signatureHEX := hex.EncodeToString(signature)
	return signatureHEX, nil
}

func VerifySignatureHEX(publicKey *rsa.PublicKey, message []byte, signatureHEX string) error {
	signature, err := hex.DecodeString(signatureHEX)
	if err != nil {
		return errors.Wrap(err, "decode from hex DecodeString")
	}
	return VerifySignature(publicKey, message, signature)
}

func VerifySignatureB64(publicKey *rsa.PublicKey, message []byte, signatureB64 string) error {
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return errors.Wrap(err, "decode from base64 DecodeString")
	}
	return VerifySignature(publicKey, message, signature)
}

func VerifySignature(publicKey *rsa.PublicKey, message []byte, signature []byte) error {
	hashed := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	return errors.Wrap(err, "verification VerifyPKCS1v15")
}
