package main

import (
	"fmt"

	"github.com/hotafrika/rsa-simple/generator"
	"github.com/hotafrika/rsa-simple/serializer"
)

func main() {
	priv, pub := generator.GenerateRsaKeyPair()

	privPEM := serializer.ExportRsaPrivateKeyAsPem(priv)
	pubPEM, _ := serializer.ExportRsaPublicKeyAsPem(pub)

	fmt.Println("Private key:")
	fmt.Println(privPEM)
	fmt.Println("Public key:")
	fmt.Println(pubPEM)
}
