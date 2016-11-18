package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

type SignedMessage struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	PubKey    string `json:"pubkey"`
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func SavePrivKey(privKey *ecdsa.PrivateKey, path string) {
	privDer, _ := x509.MarshalECPrivateKey(privKey)

	privBlk := pem.Block{
		Type:    "ECDSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDer,
	}

	f, _ := os.Create(path)
	_ = f.Chmod(os.FileMode(int(0600)))
	_ = pem.Encode(f, &privBlk)
	defer f.Close()
}

func ReadPrivKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	privBlk, _ := pem.Decode(data)

	return x509.ParseECPrivateKey(privBlk.Bytes)
}

func ReadOrGenKey() (*ecdsa.PrivateKey, error) {
	path := "ecdsa"
	key, err := ReadPrivKey(path)
	if os.IsNotExist(err) {
		key, err = GenerateKey()
		if err != nil {
			return nil, err
		}

		SavePrivKey(key, path)
	} else if err != nil {
		return nil, err
	}

	return key, nil
}

func HashMsg(msg string) []byte {
	hash := sha256.Sum256([]byte(msg))

	// Convert [32]byte to []byte
	return hash[:]
}

func SignMsg(msg string, privKey *ecdsa.PrivateKey) (string, error) {
	var signature []byte

	r, s, err := ecdsa.Sign(rand.Reader, privKey, HashMsg(msg))
	if err != nil {
		return "", err
	}

	signature = append(r.Bytes(), s.Bytes()...)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func PublicPem(privKey *ecdsa.PrivateKey) string {
	pub := privKey.PublicKey
	pubBytes := append(pub.X.Bytes(), pub.Y.Bytes()...)
	b64 := base64.StdEncoding.EncodeToString(pubBytes)

	pubBlk := pem.Block{
		Type:    "ECDSA PUBLIC KEY",
		Headers: nil,
		Bytes:   []byte(b64),
	}

	return string(pem.EncodeToMemory(&pubBlk))
}

func SignMessage(msg string, privKey *ecdsa.PrivateKey) ([]byte, error) {
	if len(msg) > 250 {
		return nil, errors.New("Message can not exceed 250 characters")
	}

	signature, err := SignMsg(msg, privKey)
	if err != nil {
		return nil, err
	}

	signed := &SignedMessage{
		Message:   msg,
		Signature: signature,
		PubKey:    PublicPem(privKey)}

	signedj, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}

	return signedj, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage:\n\tsign-please \"some-message\"")
		os.Exit(42)
	}

	privKey, err := ReadOrGenKey()
	if err != nil {
		panic(err)
	}
	if privKey == nil {
		fmt.Println(string("privKey is nil"))
	}

	arg := os.Args[1]
	signed, err := SignMessage(arg, privKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(signed))
}
