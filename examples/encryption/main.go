package main

import (
	"fmt"
	"github.com/hotafrika/rsa-simple/crypter"
	"io"
	"log"
	"os"

	"github.com/hotafrika/rsa-simple/serializer"
)

func main() {
	f, err := os.Open("keys/public.key")
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	publicKeyContent, err := io.ReadAll(f)
	if err != nil {
		log.Fatalln(err)
	}

	publicKey, err := serializer.ParseRsaPublicKeyFromPem(publicKeyContent)
	if err != nil {
		log.Fatalln(err)
	}

	message := "Have a good day!"
	label := "Happy"
	fmt.Println("Initial message:")
	fmt.Println(message)

	cipherHEX, err := crypter.EncryptHEX(publicKey, []byte(message), []byte(label))
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Cipher HEX:")
	fmt.Println(cipherHEX)

	cipherB64, err := crypter.EncryptB64(publicKey, []byte(message), []byte(label))
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Cipher Base64:")
	fmt.Println(cipherB64)

	// =====================================

	f2, err := os.Open("keys/private.key")
	if err != nil {
		log.Fatalln(err)
	}
	defer f2.Close()
	privateKeyContent, err := io.ReadAll(f2)
	if err != nil {
		log.Fatalln(err)
	}

	privateKey, err := serializer.ParseRsaPrivateKeyFromPem(privateKeyContent)
	if err != nil {
		log.Fatalln(err)
	}

	messageFromHEX, err := crypter.DecryptHEX(privateKey, cipherHEX, []byte(label))
	if err != nil {
		fmt.Println("Decryption failed!")
		return
	}
	fmt.Println("Decrypted message from HEX:")
	fmt.Println(string(messageFromHEX))

	messageFromB64, err := crypter.DecryptB64(privateKey, cipherB64, []byte(label))
	if err != nil {
		fmt.Println("Decryption failed!")
		return
	}
	fmt.Println("Decrypted message from Base64:")
	fmt.Println(string(messageFromB64))
}
