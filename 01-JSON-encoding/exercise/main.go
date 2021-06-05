package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type person struct {
	First, Last string
}

func encode(w http.ResponseWriter, r *http.Request) {
	people := []person{
		{First: "Petros", Last: "Trak"},
		{First: "Maggie", Last: "Trak"},
	}

	if err := json.NewEncoder(w).Encode(people); err != nil {
		log.Panic("Encoded bad data", err)
	}
}

// curl -XGET -H "Content-type: application/json" -d '[{"First":"Petros", "Last":"Trak"}, {"First":"Maggie", "Last":"Trak"}]' 'localhost:8080/decode'
func decode(w http.ResponseWriter, r *http.Request) {
	var people []person
	if err := json.NewDecoder(r.Body).Decode(&people); err != nil {
		log.Println("Decoded bad data", err)
	}

	fmt.Println(people)
}

func main() {
	http.HandleFunc("/encode", encode)
	http.HandleFunc("/decode", decode)
	http.ListenAndServe(":8080", nil)
}
