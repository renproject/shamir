package shamirutil

import "github.com/renproject/surge"

// UnmarshalSliceLen32 unmarshals a uint32 from the reader and interprets it as
// a slice length for a slice with elements of size elemSize in bytes. An error
// will be returned if the unmarshalling fails, or if the slice length is too
// large.
func UnmarshalSliceLen32(dst *uint32, elemSize int, buf []byte, rem int) ([]byte, int, error) {
	var l uint32
	buf, rem, err := surge.UnmarshalU32(&l, buf, rem)
	if err != nil {
		return buf, rem, err
	}

	var c uint64 = uint64(l) * uint64(elemSize)

	// Check if there was overflow in the multiplication.
	if c/uint64(l) != uint64(elemSize) {
		return buf, rem, surge.ErrLengthOverflow
	}

	if uint64(len(buf)) < c || uint64(rem) < c {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}

	*dst = l
	return buf, rem, nil
}
