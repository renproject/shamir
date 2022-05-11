package rs

import (
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/secp256k1/eea"
	"github.com/renproject/shamir/secp256k1/poly"
	"github.com/renproject/surge"
)

// Generate implements the quick.Generator interface.
func (dec Decoder) Generate(rand *rand.Rand, size int) reflect.Value {
	n := rand.Int31()
	k := rand.Int31()
	indices := make([]secp256k1.Fn, size/10)
	for i := range indices {
		indices[i] = secp256k1.RandomFn()
	}
	interpolator := poly.Interpolator{}.Generate(rand, size).Interface().(poly.Interpolator)
	eea := eea.Stepper{}.Generate(rand, size).Interface().(eea.Stepper)
	g0 := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	interpPoly := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	f1 := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	r := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	errors := make([]secp256k1.Fn, size/10)
	for i := range errors {
		errors[i] = secp256k1.RandomFn()
	}
	errorsComputed := rand.Int()&1 == 1
	decoder := Decoder{
		n: int(n), k: int(k),
		indices:      indices,
		interpolator: interpolator,
		eea:          eea,

		g0:         g0,
		interpPoly: interpPoly,
		f1:         f1, r: r,
		errors:         errors,
		errorsComputed: errorsComputed,
	}
	return reflect.ValueOf(decoder)
}

// SizeHint implements the surge.SizeHinter interface.
func (dec Decoder) SizeHint() int {
	return surge.SizeHintI32 +
		surge.SizeHintI32 +
		surge.SizeHint(dec.indices) +
		dec.interpolator.SizeHint() +
		dec.eea.SizeHint() +
		dec.g0.SizeHint() +
		dec.interpPoly.SizeHint() +
		dec.f1.SizeHint() +
		dec.r.SizeHint() +
		surge.SizeHint(dec.errors) +
		surge.SizeHint(dec.errorsComputed)
}

// Marshal implements the surge.Marshaler interface.
func (dec Decoder) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalI32(int32(dec.n), buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.MarshalI32(int32(dec.k), buf, rem)
	if err != nil {
		return buf, rem, err
	}

	buf, rem, err = surge.Marshal(dec.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}

	buf, rem, err = dec.interpolator.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = dec.eea.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = dec.g0.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = dec.interpPoly.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = dec.f1.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = dec.r.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Marshal(dec.errors, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Marshal(dec.errorsComputed, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (dec *Decoder) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	var tmp int32
	buf, rem, err := surge.UnmarshalI32(&tmp, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	dec.n = int(tmp)
	buf, rem, err = surge.UnmarshalI32(&tmp, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	dec.k = int(tmp)
	buf, rem, err = surge.Unmarshal(&dec.indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = dec.interpolator.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = dec.eea.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = dec.g0.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = dec.interpPoly.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = dec.f1.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = dec.r.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = surge.Unmarshal(&dec.errors, buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return surge.Unmarshal(&dec.errorsComputed, buf, rem)
}
