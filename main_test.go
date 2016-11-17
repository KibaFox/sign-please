package main

import (
	"encoding/json"
	"testing"
)

func TestHelloWorld(t *testing.T) {
	var result []byte
	result = HelloWorld()

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
