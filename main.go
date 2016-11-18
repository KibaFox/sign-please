package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

type SignedMessage struct {
	Message string `json:"message"`
}

func GenerateKey() {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	privDer, _ := x509.MarshalECPrivateKey(priv)

	privBlk := pem.Block{
		Type:    "ECDSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDer,
	}

	f, _ := os.Create("ecdsa")
	_ = f.Chmod(os.FileMode(int(0600)))
	_ = pem.Encode(f, &privBlk)
	defer f.Close()
}

func SignMessage(msg string) ([]byte, error) {
	if len(msg) > 250 {
		return nil, errors.New("Message can not exceed 250 characters")
	}

	signed := &SignedMessage{
		Message: msg}

	signedj, err := json.Marshal(signed)
	if err != nil {
		panic(err)
	}

	return signedj, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage:\n\tsign-please \"some-message\"")
		os.Exit(42)
	}

	GenerateKey()

	arg := os.Args[1]
	signed, err := SignMessage(arg)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(signed))
}
