package eea

import (
	"math/rand"
	"reflect"

	"github.com/renproject/shamir/secp256k1/poly"
)

// Generate implements the quick.Generator interface.
func (eea Stepper) Generate(rand *rand.Rand, size int) reflect.Value {
	size = size / 8
	rPrev := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	rNext := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	sPrev := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	sNext := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	tPrev := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	tNext := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	q := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	r := poly.Poly{}.Generate(rand, size).Interface().(poly.Poly)
	stepper := Stepper{
		rPrev: rPrev, rNext: rNext,
		sPrev: sPrev, sNext: sNext,
		tPrev: tPrev, tNext: tNext,
		q: q, r: r,
	}
	return reflect.ValueOf(stepper)
}

// SizeHint implements the surge.SizeHinter interface.
func (eea Stepper) SizeHint() int {
	return eea.rNext.SizeHint() +
		eea.rPrev.SizeHint() +
		eea.sNext.SizeHint() +
		eea.sPrev.SizeHint() +
		eea.tNext.SizeHint() +
		eea.tPrev.SizeHint() +
		eea.q.SizeHint() +
		eea.r.SizeHint()
}

// Marshal implements the surge.Marshaler interface.
func (eea Stepper) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := eea.rNext.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.rPrev.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.sNext.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.sPrev.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.tNext.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.tPrev.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.q.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return eea.r.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (eea *Stepper) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := eea.rNext.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.rPrev.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.sNext.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.sPrev.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.tNext.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.tPrev.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	buf, rem, err = eea.q.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return eea.r.Unmarshal(buf, rem)
}
