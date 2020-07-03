package util

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/renproject/surge"
)

// UnmarshalSliceLen32 unmarshals a uint32 from the reader and interprets it as
// a slice length for a slice with elements of size elemSize in bytes. An error
// will be returned if the unmarshalling fails, or if the slice length is too
// large.
func UnmarshalSliceLen32(dst *uint32, elemSize int, r io.Reader, m int) (int, error) {
	if m < 4 {
		return m, surge.ErrUnexpectedEndOfBuffer
	}

	var bs [4]byte
	n, err := io.ReadFull(r, bs[:])
	m -= n
	if err != nil {
		return m, err
	}

	// Number of curve points.
	l := binary.BigEndian.Uint32(bs[:])

	// Make sure that the multiplication in the next check won't overflow.
	if uint64(l)*uint64(elemSize) > uint64(^uint32(0)) {
		return m, errors.New("slice length too large")
	}

	// Casting m (signed) to an unsigned int is safe here. This is because it
	// is guaranteed to be positive: we check at the start of the function that
	// m >= 4, and then only subtract n which satisfies n <= 4.
	if uint32(m) < l*uint32(elemSize) {
		return m, surge.ErrUnexpectedEndOfBuffer
	}

	*dst = l
	return m, nil
}
