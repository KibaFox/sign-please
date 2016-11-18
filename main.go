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

// Representation structure for the message, signature, and the public key.
type SignedMessage struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	PubKey    string `json:"pubkey"`
}

// Generate a new ECDSA key.  Uses the nistp384 curve.
// It returns the ecdsa.PrivateKey or an error if one occurs.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// Save a private ECDSA key to disk.
// It takes an ecdsa.PrivateKey and the path as a string.
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

// Read a private ECDSA key from disk.
// It takes in a path as a string.
// It returns an ecdsa.PrivateKey or an error if one occurs.
func ReadPrivKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	privBlk, _ := pem.Decode(data)

	return x509.ParseECPrivateKey(privBlk.Bytes)
}

// Read the persisted ECDSA key from disk or generate a new one if it does not
// exist.  If the key file is not found, the new key is persisted to disk.
// It returns an ecdsa.PrivateKey or an error if one occurs.
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

// Gets the sha256 sum of a message.
// It takes a message as a string.
// It returns the sha256 sum of the message as []byte.
func HashMsg(msg string) []byte {
	hash := sha256.Sum256([]byte(msg))

	// Convert [32]byte to []byte
	return hash[:]
}

// Sign the provided message with the provided private key.
// It takes a message as a string and a private key as a ecdsa.PrivateKey.
// It returns a base64 encoded string representation of the signature and an
// error if one occurs.
func SignMsg(msg string, privKey *ecdsa.PrivateKey) (string, error) {
	var signature []byte

	r, s, err := ecdsa.Sign(rand.Reader, privKey, HashMsg(msg))
	if err != nil {
		return "", err
	}

	signature = append(r.Bytes(), s.Bytes()...)
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Get the public key in pem format where the payload is encoded in base64.
// It takes a private key as ecdsa.PrivateKey.
// It returns the public key as a string formatted as a pem where the payload is
// encoded in base64 (RFC 4648).
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

// Sign a message using ECDSA and returns the signed message in a JSON
// representation.
// It takes a message as a string and a private key as an ecdsa.PrivateKey.
// It returns the json as a []byte of the message, the signature in base64
// encoding, and the public key as a pem where the payload is base64 encoded; or
// an error if one occurs.
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

// Takes in the message as the first argument and outputs the message in json
// representation with the message, signature, and public key.
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
