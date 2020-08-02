package poly

import (
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"
)

// Generate implements the quick.Generator interface.
func (p Poly) Generate(_ *rand.Rand, size int) reflect.Value {
	poly := make(Poly, size)
	for i := range poly {
		poly[i] = secp256k1.RandomFn()
	}
	return reflect.ValueOf(poly)
}

// SizeHint implements the surge.SizeHinter interface.
func (p Poly) SizeHint() int {
	return 2*surge.SizeHintU32 + secp256k1.FnSizeMarshalled*len(p)
}

// Marshal implements the surge.Marshaler interface.
func (p Poly) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalLen(uint32(len(p)), buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalLen(uint32(cap(p)), buf, rem)
	if err != nil {
		return buf, rem, err
	}
	for _, c := range p {
		buf, rem, err = c.Marshal(buf, rem)
		if err != nil {
			return buf, rem, err
		}
	}
	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (p *Poly) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	var l, c uint32
	buf, rem, err := surge.UnmarshalLen(&l, secp256k1.FnSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.UnmarshalLen(&c, secp256k1.FnSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	if l == 0 {
		*p = make([]secp256k1.Fn, 0, c)
		return buf, rem, nil
	}
	if len(*p) < int(l) || cap(*p) < int(c) {
		*p = make(Poly, l, c)
	} else {
		*p = (*p)[:l]
	}
	for i := range *p {
		buf, rem, err = (*p)[i].Unmarshal(buf, rem)
		if err != nil {
			return buf, rem, err
		}
	}
	return buf, rem, nil
}

// Generate implements the quick.Generator interface.
func (interp Interpolator) Generate(_ *rand.Rand, size int) reflect.Value {
	n := rand.Intn(size + 1)
	m := size / (n + 1)
	basis := make([]Poly, n)
	for i := range basis {
		basis[i] = make(Poly, m)
		for j := range basis[i] {
			basis[i][j] = secp256k1.RandomFn()
		}
	}
	return reflect.ValueOf(Interpolator{basis: basis})
}

// SizeHint implements the surge.SizeHinter interface.
func (interp Interpolator) SizeHint() int { return surge.SizeHint(interp.basis) }

// Marshal implements the surge.Marshaler interface.
func (interp Interpolator) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Marshal(interp.basis, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (interp *Interpolator) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Unmarshal(&interp.basis, buf, rem)
}
