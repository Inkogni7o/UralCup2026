package store

import "testing"

func TestSessionTokensAreRandomAndOpaque(t *testing.T) {
	first, err := newSessionToken()
	if err != nil {
		t.Fatalf("newSessionToken: %v", err)
	}
	second, err := newSessionToken()
	if err != nil {
		t.Fatalf("newSessionToken: %v", err)
	}
	if first == second {
		t.Fatal("two session tokens unexpectedly match")
	}
	if !validSessionToken(first) || !validSessionToken(second) {
		t.Fatal("generated token rejected by validator")
	}
	if validSessionToken("NDI6MQ==") {
		t.Fatal("legacy base64 user-id token accepted")
	}
}
