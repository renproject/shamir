package shamir

import (
	"fmt"

	"github.com/renproject/secp256k1"
)

// ShareSize is the number of bytes in a share.
const ShareSize = 2 * secp256k1.FnSizeMarshalled

// Shares represents a slice of Shamir shares
type Shares []Share

// Share represents a single share in a Shamir secret sharing scheme.
type Share struct {
	Index, Value secp256k1.Fn
}

// NewShare constructs a new Shamir share from an index and a value.
func NewShare(index, value secp256k1.Fn) Share {
	return Share{Index: index, Value: value}
}

// Eq returns true if the two shares are equal, and false otherwise.
func (s *Share) Eq(other *Share) bool {
	return s.Index.Eq(&other.Index) && s.Value.Eq(&other.Value)
}

// IndexEq returns true if the index of the two shares are equal, and false
// otherwise.
func (s *Share) IndexEq(other *secp256k1.Fn) bool {
	return s.Index.Eq(other)
}

// Add computes the addition of the two input shares and stores the result in
// the caller. Addition is defined by adding the values but leaving the index
// unchanged.
//
// Panics: Addition only makes sense when the two input shares have the same
// index. If they do not, this function wil panic.
func (s *Share) Add(a, b *Share) {
	if !a.Index.Eq(&b.Index) {
		panic(fmt.Sprintf(
			"cannot add shares with different indices: lhs has index %v and rhs has index %v",
			a.Index,
			b.Index,
		))
	}

	s.Index = a.Index
	s.Value.Add(&a.Value, &b.Value)
}

// AddConstant computes the addition of the input share and the given constant
// and stores the result in the caller. Addition is defined by adding the
// constant to the share value but leaving the index unchanged.
func (s *Share) AddConstant(other *Share, c *secp256k1.Fn) {
	s.Index = other.Index
	s.Value.Add(&other.Value, c)
}

// Scale multiplies the input share by a constant and then stores it in the
// caller. This is defined as multiplying the share value by the scale, and
// leaving the index unchanged.
func (s *Share) Scale(other *Share, scale *secp256k1.Fn) {
	s.Index = other.Index
	s.Value.Mul(&other.Value, scale)
}

// ShareSecret creates Shamir shares for the given secret at the given
// threshold, and stores them in the given destination slice. In the returned
// Shares, there will be one share for each index in the indices that were used
// to construct the Sharer. If k is larger than the number of indices, in which
// case it would be impossible to reconstruct the secret, an error is returned.
//
// Panics: This function will panic if the destination shares slice has a
// capacity less than n (the number of indices).
func ShareSecret(dst *Shares, indices []secp256k1.Fn, secret secp256k1.Fn, k int) error {
	coeffs := make([]secp256k1.Fn, k)
	return ShareAndGetCoeffs(dst, coeffs, indices, secret, k)
}

// ShareAndGetCoeffs is the same as ShareSecret, but uses the provided slice to
// store the generated coefficients of the sharing polynomial. If this function
// successfully returns, this slice will contain the coefficients of the
// sharing polynomial, where index 0 is the constant term.
//
// Panics: This function will panic if the destination shares slice has a
// capacity less than n (the number of indices) or the coefficients slice has
// length less than k, or any of the given indices is the zero element.
func ShareAndGetCoeffs(dst *Shares, coeffs, indices []secp256k1.Fn, secret secp256k1.Fn, k int) error {
	for _, index := range indices {
		if index.IsZero() {
			panic("cannot create share for index zero")
		}
	}
	if k > len(indices) {
		return fmt.Errorf(
			"reconstruction threshold too large: expected k <= %v, got k = %v",
			len(indices), k,
		)
	}
	setRandomCoeffs(coeffs, secret, k)

	// Set shares
	// NOTE: This panics if the destination slice does not have the required
	// capacity.
	*dst = (*dst)[:len(indices)]
	var eval secp256k1.Fn
	for i, ind := range indices {
		polyEval(&eval, &ind, coeffs)
		(*dst)[i].Index = ind
		(*dst)[i].Value = eval
	}

	return nil
}

// Sets the coefficients of the Sharer to represent a random degree k-1
// polynomial with constant term equal to the given secret.
//
// Panics: This function will panic if k is greater than len(coeffs).
func setRandomCoeffs(coeffs []secp256k1.Fn, secret secp256k1.Fn, k int) {
	coeffs = coeffs[:k]
	coeffs[0] = secret

	// NOTE: If k > len(coeffs), then this will panic when i > len(coeffs).
	for i := 1; i < k; i++ {
		coeffs[i] = secp256k1.RandomFn()
	}
}

// Evaluates the polynomial defined by the given coefficients at the point x
// and stores the result in y. Modifies y, but leaves x and coeffs unchanged.
// Normalizes y, so this this is not neccesary to do manually after calling
// this function.
//
// Panics: This function assumes that len(coeffs) is at least 1 and not nil. If
// it is not, it will panic. It does not make sense to call this function if
// coeffs is the empty (or nil) slice.
func polyEval(y, x *secp256k1.Fn, coeffs []secp256k1.Fn) {
	// NOTE: This will panic if len(coeffs) is less than 1 or if coeffs is nil.
	*y = coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		y.Mul(y, x)
		y.Add(y, &coeffs[i])
	}
}

// Open computes the secret corresponding to the given shares. This is
// equivalent to interpolating the polynomial that passes through the given
// points, and returning the constant term. It is assumed that all shares have
// different indices. Further properties that need to be hold if this function
// is to correctly reconstruct the secret for a sharing with threshoold k are:
//	- There are at least k shares.
//	- All shares are valid, in the sense that they have not been maliciously
//		modified.
func Open(shares Shares) secp256k1.Fn {
	var num, denom, res, tmp secp256k1.Fn
	res.SetU16(0)
	for i := range shares {
		num.SetU16(1)
		denom.SetU16(1)
		for j := range shares {
			if shares[i].Index.Eq(&shares[j].Index) {
				continue
			}
			tmp.Negate(&shares[i].Index)
			tmp.Add(&tmp, &shares[j].Index)
			denom.Mul(&denom, &tmp)
			num.Mul(&num, &shares[j].Index)
		}
		denom.Inverse(&denom)
		tmp.Mul(&num, &denom)
		tmp.Mul(&tmp, &shares[i].Value)
		res.Add(&res, &tmp)
	}
	return res
}
