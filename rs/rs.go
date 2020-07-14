package rs

import (
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/eea"
	"github.com/renproject/shamir/poly"
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
		n, k,
		indices,
		interpolator,
		eea,

		g0,
		interpPoly,
		f1, r,
		errors,
		errorsComputed,
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
