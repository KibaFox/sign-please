package main

import "encoding/json"
import "fmt"

type SignedMessage struct {
	Message string `json:"message"`
}

func HelloWorld() []byte {
	msg := &SignedMessage{
		Message: "hello-world"}

	json, _ := json.Marshal(msg)
	return json
}

func main() {
	msg := &SignedMessage{
		Message: "hello-world"}

	json, _ := json.Marshal(msg)
	fmt.Println(string(json))
}
