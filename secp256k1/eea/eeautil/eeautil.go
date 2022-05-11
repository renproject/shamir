package eeautil

import "math/rand"

// Contains returns true if the given slice contains the given int.
func Contains(list []int, ind int) bool {
	for _, v := range list {
		if ind == v {
			return true
		}
	}
	return false
}

// RandomSubset sets the destintation slice to be a random subset of the
// numbers 0, ..., l of size n.
func RandomSubset(dst *[]int, n, l int) {
	*dst = (*dst)[:0]
	for i := 0; i < n; i++ {
		ind := rand.Intn(l)

		for Contains(*dst, ind) {
			if ind == l-1 {
				ind = 0
			} else {
				ind++
			}
		}

		*dst = append(*dst, ind)
	}
}
