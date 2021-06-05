package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type person struct {
	FirstName, LastName string
}

func main() {
	// p1 := person{
	// 	FirstName: "Petros",
	// 	LastName:  "Trak",
	// }

	// bs, err := json.Marshal(p1)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println(string(bs))
	// fmt.Println("***")

	// var p2 person
	// if err := json.Unmarshal(bs, &p2); err != nil {
	// 	log.Println(err)
	// }

	// fmt.Println(p2)

	http.HandleFunc("/encode", encode)
	http.HandleFunc("/decode", decode)
	http.ListenAndServe(":8080", nil)

}

func encode(w http.ResponseWriter, r *http.Request) {
	p1 := person{
		FirstName: "Petros",
		LastName:  "Trak",
	}

	if err := json.NewEncoder(w).Encode(p1); err != nil {
		log.Println("Encoded bad data", err)
	}
}

func decode(w http.ResponseWriter, r *http.Request) {
	var p person
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		log.Println("Decode bad data", err)
	}

	fmt.Printf("Decoded person: %v\n", p)
}
