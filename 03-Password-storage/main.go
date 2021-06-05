package main

import (
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
