package rs

import (
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/eea"
	"github.com/renproject/shamir/poly"
	"github.com/renproject/surge"
)

// Decoder can do Reed-Solomon decoding on given codewords. RS code words are
// points on some unknown polynomial. The x coordinates of these points are
// called the indices. Each instance of a decoder corresponds to a specific set
// of indices; this allows multiple decodings to use the same relatively
// expensive setup.
type Decoder struct {
	n, k         int
	indices      []secp256k1.Fn
	interpolator poly.Interpolator
	eea          eea.Stepper

	g0             poly.Poly
	interpPoly     poly.Poly
	f1, r          poly.Poly
	errors         []secp256k1.Fn
	errorsComputed bool
}

// NewDecoder constructs a new decoder instance from a given set of indices
// where k is the maximum degree of the polynomial for the codewords.  This
// decoder can be used to decode any codeword that has the same set of indices.
// That is, if the decoder is constructed from indices `{x0, x1, ..., xn}`,
// then for a codeword `{y0, y1, ..., yn}` the decoder will attempt to find a
// polynomial `f` such that `f(xi) = yi` for as many `i` as possible. The
// number of points that constitute a codeword, `n`, is determined by the
// length of the index slice. The values in the index slice are copied, and so
// are safe to modify after being given to this constructor.
func NewDecoder(inds []secp256k1.Fn, k int) Decoder {
	indices := make([]secp256k1.Fn, len(inds))
	copy(indices, inds)
	n := len(indices)
	interpolator := poly.NewInterpolator(indices)
	eea := eea.NewStepperWithCapacity(n + 1)
	g0 := poly.NewWithCapacity(n + 1)
	interpPoly := poly.NewWithCapacity(n)
	f1 := poly.NewWithCapacity(n)
	r := poly.NewWithCapacity(n)
	errors := make([]secp256k1.Fn, k)
	errorsComputed := false

	// Construct g0
	g0[0].SetU16(1)
	linearTerm := poly.NewWithCapacity(2)
	linearTerm = linearTerm[:2]
	for i := range indices {
		*linearTerm.Coefficient(0) = inds[i]
		linearTerm.Coefficient(0).Negate(linearTerm.Coefficient(0))
		linearTerm.Coefficient(1).SetU16(1)
		g0.Mul(g0, linearTerm)
	}

	return Decoder{
		n: n, k: k,
		indices:      indices,
		interpolator: interpolator,
		eea:          eea,

		g0:         g0,
		interpPoly: interpPoly,
		f1:         f1, r: r,
		errors:         errors,
		errorsComputed: errorsComputed,
	}
}

// Decode executes the RS decoding algorithm to try to recover the encoded
// polynomial. If decoding was successful, the polynomial is returned and the
// returned boolean is true. Otherwise, the polynomial is nil and the boolean
// is false. Decoding will fail if there are more than (n - k)/2 errors, but
// less than n - k. If there are more than n - k errors, the output behaviour
// is undefined.
func (dec *Decoder) Decode(values []secp256k1.Fn) (*poly.Poly, bool) {
	threshold := (dec.n + dec.k) / 2
	dec.errorsComputed = false

	// Interpolate
	dec.interpolator.Interpolate(values, &dec.interpPoly)

	// Partial GCD
	dec.eea.Init(dec.g0, dec.interpPoly)
	for dec.eea.Rem().Degree() >= threshold {
		dec.eea.Step()
	}

	// Long division
	poly.Divide(*dec.eea.Rem(), *dec.eea.T(), &dec.f1, &dec.r)

	if dec.r.IsZero() && dec.f1.Degree() < dec.k {
		return &dec.f1, true
	}
	return nil, false
}

// ErrorIndices returns a slice of indices that correspond to the error
// locations for the most recent execution of the decoding algorithm. If the
// decoding algorithm has not been run yet or there are no errors, a nil slice
// will be returned.
func (dec *Decoder) ErrorIndices() []secp256k1.Fn {
	// If we have already computed the errors for this decoding, short ciruit
	// and yield the cached result.
	if dec.errorsComputed {
		return dec.errors
	}

	// In this case the decoding algorithm has not yet been run.
	if dec.eea.T().IsZero() {
		return nil
	}

	var value secp256k1.Fn
	dec.errorsComputed = true
	dec.errors = dec.errors[:0]

	for _, index := range dec.indices {
		value = dec.eea.T().Evaluate(index)
		if value.IsZero() {
			dec.errors = append(dec.errors, index)
		}
	}

	if len(dec.errors) == 0 {
		return nil
	}

	return dec.errors
}

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
