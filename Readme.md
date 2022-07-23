#### `rsa-simple` is a tiny helper lib for fast work with RSA keys.

Using this lib you can generate keys, marshall/unmarshall it, create signature and verify it.

For simplicity under the hood it uses some hardcoded values:
- **4096** bits for key pair generation;
- **PKCS8** format for marshalling/unmarshalling of private keys;
- **PKIX** format for marshalling/unmarshalling of public keys;
- **SHA256** algorithm for message hast generation;
- **PKCS1v15** for signature creation and verification.

#### Examples:

To generate private and public RSA keys:
```go
func main() {
    priv, pub := generator.GenerateRsaKeyPair()
}
```

To generate key pair and print it in pretty way:
```go
func main() {
    priv, pub := generator.GenerateRsaKeyPair()
    
    privPEM := serializer.ExportRsaPrivateKeyAsPem(priv)
    pubPEM, _ := serializer.ExportRsaPublicKeyAsPem(pub)
    
    fmt.Println("Private key:")
    fmt.Println(privPEM)
    fmt.Println("Public key:")
    fmt.Println(pubPEM)
}
```

To read private key from file:
```go
func main() {
    f, _ := os.Open("private.key")
    privateKeyContent, _ := io.ReadAll(f)
    privateKey, _ := serializer.ParseRsaPrivateKeyFromPem(privateKeyContent)
}
```

To read public key from file:
```go
func main() {
    f, _ := os.Open("public.key")
    publicKeyContent, _ := io.ReadAll(f)
    publicKey, _ := serializer.ParseRsaPublicKeyFromPem(publicKeyContent)
}
```

To get signature (in HEX string) of message:
```go
func main(){
    privateKey, publicKey := generator.GenerateRsaKeyPair()
    ...
    signatureHEX, _ := signer.GetSignatureHEX(privateKey, message)
}
```

To verify signature (in HEX string):
```go
func main(){
    privateKey, publicKey := generator.GenerateRsaKeyPair()
    ...
    signatureHEX, _ := signer.GetSignatureHEX(privateKey, message)
    ...
    err = signer.VerifySignatureHEX(publicKey, message, signatureHEX)
}
```