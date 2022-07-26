package serializer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// ExportRsaPrivateKeyAsPem creates serialized representation of rsa.PrivateKey.
// It could be saved to a text file for example.
func ExportRsaPrivateKeyAsPem(privateKey *rsa.PrivateKey) []byte {
	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return privateKeyPEM
}

// ParseRsaPrivateKeyFromPem creates rsa.PrivateKey from serialized format.
func ParseRsaPrivateKeyFromPem(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	privateKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	privateKey, ok := privateKeyInterface.(*rsa.PrivateKey)
	if ok {
		return privateKey, nil
	}

	return nil, errors.New("private key type is not RSA")
}

// ExportRsaPublicKeyAsPem creates serialized representation of rsa.PublicKey.
// It could be saved to a text file for example.
func ExportRsaPublicKeyAsPem(publicKey *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)

	return publicKeyPEM, nil
}

// ParseRsaPublicKeyFromPem creates rsa.PublicKey from serialized format.
func ParseRsaPublicKeyFromPem(publicKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if ok {
		return publicKey, nil
	}
	return nil, errors.New("public key type is not RSA")
}
