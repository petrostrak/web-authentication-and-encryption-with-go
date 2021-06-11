package main

import "fmt"

const (
	totalStars = 5
)

func generateStar(num int) {
	for i := 0; i < totalStars; i++ {
		if i > num-1 {
			fmt.Print("\u2606 ")
			continue
		}
		fmt.Print("\u2605 ")
	}

	fmt.Println()
}

func main() {
	generateStar(0)
}
