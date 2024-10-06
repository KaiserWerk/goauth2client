package goauth2client

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateState generates a state to be supplied in an auth request and to be tested
// against in the response. It is generated from 20 random bytes, encoded to base64.
func GenerateState() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
