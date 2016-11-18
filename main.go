package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type SignedMessage struct {
	Message string `json:"message"`
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

	arg := os.Args[1]
	signed, err := SignMessage(arg)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(signed))
}
