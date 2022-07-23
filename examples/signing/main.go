package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/hotafrika/rsa-simple/serializer"
	"github.com/hotafrika/rsa-simple/signer"
)

func main() {
	f, err := os.Open("keys/private.key")
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	privateKeyContent, err := io.ReadAll(f)
	if err != nil {
		log.Fatalln(err)
	}

	privateKey, err := serializer.ParseRsaPrivateKeyFromPem(privateKeyContent)
	if err != nil {
		log.Fatalln(err)
	}

	messageString := "Have a good day!"
	message := []byte(messageString)

	signatureHEX, err := signer.GetSignatureHEX(privateKey, message)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(signatureHEX)

	// ====================

	f2, err := os.Open("keys/public.key")
	if err != nil {
		log.Fatalln(err)
	}
	defer f2.Close()
	publicKeyContent, err := io.ReadAll(f2)
	if err != nil {
		log.Fatalln(err)
	}

	publicKey, err := serializer.ParseRsaPublicKeyFromPem(publicKeyContent)
	if err != nil {
		log.Fatalln(err)
	}

	err = signer.VerifySignatureHEX(publicKey, message, signatureHEX)
	if err != nil {
		fmt.Println("Verification failed!")
		return
	}
	fmt.Println("Verification successful!")
}
