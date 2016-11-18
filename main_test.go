package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

// This constant contains an ecdsa private key as a string in PEM format where
// the payload is encoded in ASN.1, DER format.
const EcdsaPrivateKey = `
-----BEGIN ECDSA PRIVATE KEY-----
MIGkAgEBBDDRwBjK8SS7R1etLPfQ0oHI+Njc97FrxNqFfee0KQEh4/Ww2lSQ230q
hfQfHAaNAAGgBwYFK4EEACKhZANiAASeppu7RMiU0QzmxgDd9pH0WcTf+voZCiM0
HWLt1X1X+ZfkTxjmDbzMwKJxmumU5/9AIzX1C/Qsav6AfeClkEXC9UV3L9LuH2dz
ugBjTYxzRJbip7ySLoQTP0/UDMj5SJo=
-----END ECDSA PRIVATE KEY-----`

// Gets the ECDSA private key from the constant.
// It returns an ecdsa.PrivateKey.
func getEcdsaPrivKey() *ecdsa.PrivateKey {
	privBlk, _ := pem.Decode([]byte(EcdsaPrivateKey))
	privKey, _ := x509.ParseECPrivateKey(privBlk.Bytes)
	return privKey
}

func TestEchoHelloWorld(t *testing.T) {
	t.Log("Using message \"hello-world\"... (expecting \"hello-world\")")

	message := "hello-world"

	result, err := SignMessage(message, getEcdsaPrivKey())
	if err != nil {
		t.Errorf("Error creating message: %s", err)
	}

	msg := SignedMessage{}
	if err := json.Unmarshal(result, &msg); err != nil {
		t.Errorf("Error parsing json: %s", err)
	}

	if msg.Message != "hello-world" {
		t.Errorf(
			"Expected message to be \"hello-world\", but got %s",
			msg.Message)
	}
}

func Test251CharacterMessage(t *testing.T) {
	t.Log("Using a message with 251 characters... (expecting err)")

	message := "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

	_, err := SignMessage(message, getEcdsaPrivKey())
	if err == nil {
		t.Errorf("Expected there to be an error at 251 characters")
	}
}

func Test250CharacterMessage(t *testing.T) {
	t.Log("Using a message with 250 characters... (expecting no err)")

	message := "**********************************************************************************************************************************************************************************************************************************************************"

	_, err := SignMessage(message, getEcdsaPrivKey())
	if err != nil {
		t.Errorf("Did not expect error at 250 characters: %s", err)
	}
}
