package main

import "encoding/json"
import "fmt"
import "os"

type SignedMessage struct {
	Message string `json:"message"`
}

func SignMessage(msg string) []byte {
	signed := &SignedMessage{
		Message: msg}

	signedj, err := json.Marshal(signed)
	if err != nil {
		panic(err)
	}

	return signedj
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage:\n\tsign-please \"some-message\"")
		os.Exit(42)
	}

	arg := os.Args[1]
	signed := SignMessage(arg)
	fmt.Println(string(signed))
}
