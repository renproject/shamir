package secp256k1

import (
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"
)

// Generate implements the quick.Generator interface.
func (s Share) Generate(_ *rand.Rand, _ int) reflect.Value {
	return reflect.ValueOf(NewShare(secp256k1.RandomFn(), secp256k1.RandomFn()))
}

// SizeHint implements the surge.SizeHinter interface.
func (s Share) SizeHint() int { return s.Index.SizeHint() + s.Value.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (s Share) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := s.Index.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	return s.Value.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (s *Share) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := s.Index.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	return s.Value.Unmarshal(buf, rem)
}

// SizeHint implements the surge.SizeHinter interface.
func (shares Shares) SizeHint() int { return surge.SizeHintU32 + ShareSize*len(shares) }

// Marshal implements the surge.Marshaler interface.
func (shares Shares) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalU32(uint32(len(shares)), buf, rem)
	if err != nil {
		return buf, rem, err
	}

	for i := range shares {
		buf, rem, err = shares[i].Marshal(buf, rem)
		if err != nil {
			return buf, rem, err
		}
	}

	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (shares *Shares) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	var l uint32
	buf, rem, err := surge.UnmarshalLen(&l, ShareSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}

	if *shares == nil {
		*shares = make(Shares, 0, l)
	}

	*shares = (*shares)[:0]
	for i := uint32(0); i < l; i++ {
		*shares = append(*shares, Share{})
		buf, rem, err = (*shares)[i].Unmarshal(buf, rem)
		if err != nil {
			return buf, rem, err
		}
	}
	return buf, rem, nil
}
