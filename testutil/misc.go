package testutil

import "math/rand"

func Max(a, b int) int {
	if a <= b {
		return b
	}
	return a
}

// Returns a random number x such that lower <= x <= upper.
func RandRange(lower, upper int) int {
	return rand.Intn(upper+1-lower) + lower
}
