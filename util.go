package shamir

import (
	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"
)

func unmarshalSliceLen32(dst *uint32, elemSize int, buf []byte, rem int) ([]byte, int, error) {
	var l uint32
	buf, rem, err := surge.UnmarshalU32(&l, buf, rem)
	if err != nil {
		return buf, rem, err
	}

	var c uint64 = uint64(l) * uint64(elemSize)

	// Check if there was overflow in the multiplication.
	if c/uint64(elemSize) != uint64(l) {
		return buf, rem, surge.ErrLengthOverflow
	}

	if uint64(rem) < c {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}

	*dst = l
	return buf, rem, nil
}

func marshalIndices(indices []secp256k1.Fn, buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalU32(uint32(len(indices)), buf, rem)
	if err != nil {
		return buf, rem, err
	}

	for i := range indices {
		buf, rem, err = indices[i].Marshal(buf, rem)
		if err != nil {
			return buf, rem, err
		}
	}

	return buf, rem, nil
}

func unmarshalIndices(dst *[]secp256k1.Fn, buf []byte, rem int) ([]byte, int, error) {
	var l uint32
	buf, rem, err := unmarshalSliceLen32(&l, secp256k1.FnSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}

	if *dst == nil {
		*dst = make([]secp256k1.Fn, 0)
	}

	*dst = (*dst)[:0]
	for i := uint32(0); i < l; i++ {
		*dst = append(*dst, secp256k1.Fn{})
		buf, rem, err = (*dst)[i].Unmarshal(buf, rem)
		if err != nil {
			return buf, rem, err
		}
	}

	return buf, rem, nil
}
