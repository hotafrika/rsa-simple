package generator

import (
	"crypto/rand"
	"crypto/rsa"
)

const bitSize = 4096

// GenerateRsaKeyPair generates rsa.PrivateKey and rsa.PublicKey pair.
func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, bitSize)
	return privateKey, &privateKey.PublicKey
}
