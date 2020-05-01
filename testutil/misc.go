package testutil

import (
	"encoding/binary"
	"errors"
	"math/rand"

	"github.com/renproject/secp256k1-go"
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

// RandomSliceBytes fills the destination byte slice by filling n lots of b
// bytes, where each block of b bytes is filled using the fill argument.
func RandomSliceBytes(dst []byte, n, b int, fill func([]byte)) {
	binary.BigEndian.PutUint32(dst[:4], uint32(n))
	for i := 0; i < n; i++ {
		fill(dst[4+i*b:])
	}
}

// FillRandSecp fills the destination byte slice with data corresponding to a
// random element of the secp256k1 field.
func FillRandSecp(dst []byte) {
	x := secp256k1.RandomSecp256k1N()
	x.GetB32(dst[:32])
}
