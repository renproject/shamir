package util

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/renproject/surge"
)

func UnmarshalSliceLen32(dst *uint32, elemSize int, r io.Reader, m int) (int, error) {
	if m < 4 {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [4]byte
	n, err := io.ReadFull(r, bs[:])
	m -= n
	if err != nil {
		return m, err
	}

	// Number of curve points.
	l := binary.BigEndian.Uint32(bs[:])

	if uint64(l)*uint64(elemSize) > uint64(^uint32(0)) {
		return m, errors.New("slice length too large")
	}

	// Casting m (signed) to an unsigned int is safe here. This is because it
	// is guaranteed to be positive: we check at the start of the function that
	// m >= 4, and then only subtract n which satisfies n <= 4.
	if uint32(m) < l*uint32(elemSize) {
		return m, surge.ErrMaxBytesExceeded
	}

	*dst = l
	return m, nil
}
