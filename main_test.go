package main

import (
	"encoding/json"
	"testing"
)

func TestEchoHelloWorld(t *testing.T) {
	var message = "hello-world"

	result, err := SignMessage(message)
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

func TestCharacterLimit(t *testing.T) {
	var message = "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

	_, err := SignMessage(message)
	if err == nil {
		t.Errorf("Expected there to be an error at 251 characters")
	}

	message = "**********************************************************************************************************************************************************************************************************************************************************"

	_, err = SignMessage(message)
	if err != nil {
		t.Errorf("Did not expect error at 250 characters: %s", err)
	}
}
