package main

import (
	"encoding/json"
	"testing"
)

func TestSignMessage(t *testing.T) {
	var message = "hello-world"

	var result []byte
	result = SignMessage(message)

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
