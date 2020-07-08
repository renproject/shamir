package shamirutil

import (
	"math/rand"
)

// Max returns the maximum of the two given ints.
func Max(a, b int) int {
	if a <= b {
		return b
	}
	return a
}

// RandRange returns a random number x such that lower <= x <= upper.
func RandRange(lower, upper int) int {
	return rand.Intn(upper+1-lower) + lower
}
