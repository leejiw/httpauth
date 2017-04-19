package httpauth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
)

func TestBasicAuthAuthenticateWithFunc(t *testing.T) {
	requiredUser := "jqpublic"
	requiredPass := "secret.sauce"

	r := &http.Request{Method: "GET"}

	// Dumb test function
	fn := func(u, p string, req *http.Request) bool {
		return u == requiredUser && p == requiredPass && req == r
	}

	// Provide a minimal test implementation.
	authOpts := AuthOptions{
		Realm:    "Restricted",
		AuthFunc: fn,
	}

	b := &basicAuth{opts: authOpts}

	if b.authenticate(nil) {
		t.Fatal("Should not succeed when http.Request is nil")
	}

	// Provide auth data, but no Authorization header
	if b.authenticate(r) != false {
		t.Fatal("No Authorization header supplied.")
	}

	// Initialise the map for HTTP headers
	r.Header = http.Header(make(map[string][]string))

	// Set a malformed/bad header
	r.Header.Set("Authorization", "    Basic")
	if b.authenticate(r) != false {
		t.Fatal("Malformed Authorization header supplied.")
	}

	// Test correct credentials
	auth := base64.StdEncoding.EncodeToString([]byte("jqpublic:secret.sauce"))
	r.Header.Set("Authorization", "Basic "+auth)
	if b.authenticate(r) != true {
		t.Fatal("Failed on correct credentials")
	}

	// Test incorrect credentials
	auth = base64.StdEncoding.EncodeToString([]byte("jqpublic:hackydoo"))
	r.Header.Set("Authorization", "Basic "+auth)
	if b.authenticate(r) == true {
		t.Fatal("Success when expecting failure")
	}
}

func TestBasicAuthAuthenticate(t *testing.T) {
	// Provide a minimal test implementation.
	authOpts := AuthOptions{
		Realm:    "Restricted",
		User:     "test-user",
		Password: "plain-text-password",
	}

	b := &basicAuth{
		opts: authOpts,
	}

	r := &http.Request{Method: "GET"}

	// Provide auth data, but no Authorization header
	if b.authenticate(r) != false {
		t.Fatal("No Authorization header supplied.")
	}

	// Initialise the map for HTTP headers
	r.Header = http.Header(make(map[string][]string))

	// Set a malformed/bad header
	r.Header.Set("Authorization", "    Basic")
	if b.authenticate(r) != false {
		t.Fatal("Malformed Authorization header supplied.")
	}

	// Test correct credentials
	auth := base64.StdEncoding.EncodeToString([]byte(b.opts.User + ":" + b.opts.Password))
	r.Header.Set("Authorization", "Basic "+auth)
	if b.authenticate(r) != true {
		t.Fatal("Failed on correct credentials")
	}
}

func TestHashedBasicAuthAuthenticate(t *testing.T) {
	password := "hashed-text-password"
	salt := "test-salt"
	hashed := sha256.Sum256([]byte(password + salt))
	hashedString := fmt.Sprintf("%x", hashed) // to store in password field

	// Provide a minimal test implementation.
	authOpts := AuthOptions{
		Realm:    "Restricted",
		User:     "test-user",
		Password: hashedString,
		Salt:     salt,
	}

	b := &basicAuth{
		opts: authOpts,
	}
	b.opts.AuthFunc = b.hashedBasicAuthFunc

	r := &http.Request{Method: "GET"}

	// Provide auth data, but no Authorization header
	if b.authenticate(r) != false {
		t.Fatal("No Authorization header supplied.")
	}

	// Initialise the map for HTTP headers
	r.Header = http.Header(make(map[string][]string))

	// Set a malformed/bad header
	r.Header.Set("Authorization", "    Basic")
	if b.authenticate(r) != false {
		t.Fatal("Malformed Authorization header supplied.")
	}

	// Test correct credentials
	auth := base64.StdEncoding.EncodeToString([]byte(b.opts.User + ":" + password))
	r.Header.Set("Authorization", "Basic "+auth)
	if b.authenticate(r) != true {
		t.Fatal("Failed on correct credentials")
	}
}

func TestBasicAuthAuthenticateWithoutUserAndPass(t *testing.T) {
	b := basicAuth{opts: AuthOptions{}}

	r := &http.Request{Method: "GET"}

	// Provide auth data, but no Authorization header
	if b.authenticate(r) != false {
		t.Fatal("No Authorization header supplied.")
	}

	// Initialise the map for HTTP headers
	r.Header = http.Header(make(map[string][]string))

	// Test correct credentials
	auth := base64.StdEncoding.EncodeToString([]byte(b.opts.User + ":" + b.opts.Password))
	r.Header.Set("Authorization", "Basic "+auth)
	if b.authenticate(r) != false {
		t.Fatal("Success when expecting failure")
	}
}
