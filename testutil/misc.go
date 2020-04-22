package testutil

import (
	"errors"
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

// BoundedWriter is a dummy Writer that will only write up to a maximum number
// of bytes, after which writes will error.
type BoundedWriter struct {
	max, curr int
}

// NewBoundedWriter constructs a new BoundedWriter with the given maximum
// number of writes.
func NewBoundedWriter(max int) BoundedWriter {
	curr := 0
	return BoundedWriter{max, curr}
}

// Write implements the io.Writer interface.
func (rw *BoundedWriter) Write(p []byte) (int, error) {
	if rw.curr+len(p) > rw.max {
		n := rw.max - rw.curr
		rw.curr = rw.max
		return n, errors.New("bound exceeded")
	}
	rw.curr += len(p)
	return len(p), nil
}
