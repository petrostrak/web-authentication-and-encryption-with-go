package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func hashPassword(pwd string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error while generating bcrypt hash from password: %w", err)
	}

	return bs, nil
}

func comparePassword(pwd string, hashedPwd []byte) error {
	if err := bcrypt.CompareHashAndPassword(hashedPwd, []byte(pwd)); err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}

	return nil
}

// generateKey will create a key of 64 bytes needed for hmac.New() func.
func generateKey() []byte {
	var key []byte
	for i := 1; i < 64; i++ {
		key = append(key, byte(i))
	}

	return key
}

// HMAC is a cryptographic signing-in algorith
func signMessage(msg []byte) ([]byte, error) {
	// First we have to create the hmac hasher
	h := hmac.New(sha512.New, generateKey())
	if _, err := h.Write(msg); err != nil {
		return nil, fmt.Errorf("error in signMessage while hashing message: %w", err)
	}

	signature := h.Sum(nil)

	return signature, nil
}

// checkSig compares the msg and the signature
//
// We send the msg and the signature to the user as a bearer token,
// the user sends it back to us and then we compare those two if
// they are equal.
func checkSig(msg, sig []byte) (bool, error) {
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("error in checkSig while getting signature of message: %w", err)
	}

	same := hmac.Equal(newSig, sig)

	return same, nil
}

func main() {
	pass := "123456789"

	hashedPass, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}

	if err := comparePassword(pass, []byte(hashedPass)); err != nil {
		log.Fatalln("Not logged in")
	}

	fmt.Println("Logged in!")

}
