package shamir

import (
	"fmt"
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"
)

// ShareSize is the number of bytes in a share.
const ShareSize = 2 * secp256k1.FnSizeMarshalled

// Shares represents a slice of Shamir shares
type Shares []Share

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

// Share represents a single share in a Shamir secret sharing scheme.
type Share struct {
	Index, Value secp256k1.Fn
}

// NewShare constructs a new Shamir share from an index and a value.
func NewShare(index, value secp256k1.Fn) Share {
	return Share{Index: index, Value: value}
}

// Generate implements the quick.Generator interface.
func (s Share) Generate(_ *rand.Rand, _ int) reflect.Value {
	return reflect.ValueOf(NewShare(secp256k1.RandomFn(), secp256k1.RandomFn()))
}

// Eq returns true if the two shares are equal, and false otherwise.
func (s *Share) Eq(other *Share) bool {
	return s.Index.Eq(&other.Index) && s.Value.Eq(&other.Value)
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
// length less than k.
func ShareAndGetCoeffs(dst *Shares, coeffs, indices []secp256k1.Fn, secret secp256k1.Fn, k int) error {
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

// A Reconstructor is responsible for reconstructing shares into their
// corresponding secret. Each instance can only perform reconstructions for a
// given fixed set of indices.
//
// NOTE: This struct is not safe for concurrent use.
type Reconstructor struct {
	indices    []secp256k1.Fn
	fullProd   []secp256k1.Fn
	indInv     []secp256k1.Fn
	indInts    []int
	seen       []bool
	complement []int
}

// Generate implements the quick.Generator interface.
func (r Reconstructor) Generate(rand *rand.Rand, size int) reflect.Value {
	indices := make([]secp256k1.Fn, rand.Intn(size))
	for i := range indices {
		indices[i] = secp256k1.RandomFn()
	}
	return reflect.ValueOf(NewReconstructor(indices))
}

// SizeHint implements the surge.SizeHinter interface.
func (r Reconstructor) SizeHint() int {
	return surge.SizeHintU32 + len(r.indices)*secp256k1.FnSizeMarshalled
}

// Marshal implements the surge.Marshaler interface.
func (r Reconstructor) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return marshalIndices(r.indices, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (r *Reconstructor) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	var indices []secp256k1.Fn
	var err error

	buf, rem, err = unmarshalIndices(&indices, buf, rem)
	if err != nil {
		return buf, rem, err
	}

	*r = NewReconstructor(indices)

	return buf, rem, nil
}

// N returns the number of players associated with this reconstructor instance.
// This is equal to the number of indices it was constructed with.
func (r *Reconstructor) N() int {
	return len(r.indices)
}

// NewReconstructor returns a new Reconstructor instance for the given indices.
func NewReconstructor(indices []secp256k1.Fn) Reconstructor {
	indicesCopy := make([]secp256k1.Fn, len(indices))
	copy(indicesCopy, indices)

	fullProd := make([]secp256k1.Fn, len(indices))
	indInv := make([]secp256k1.Fn, len(indices))
	indInts := make([]int, len(indices))
	seen := make([]bool, len(indices))
	complement := make([]int, len(indices))

	// Precopmuted data
	var neg, inv secp256k1.Fn
	for i := range indices {
		fullProd[i].SetU16(1)
		neg.Negate(&indices[i])
		for j := range indices {
			if i == j {
				continue
			}

			inv.Add(&indices[j], &neg)
			inv.Inverse(&inv)
			inv.Mul(&inv, &indices[j])

			fullProd[i].Mul(&fullProd[i], &inv)
		}
	}
	for i, ind := range indices {
		indInv[i].Inverse(&ind)
	}

	return Reconstructor{indicesCopy, fullProd, indInv, indInts, seen, complement}
}

// Open returns the secret corresponding to the given shares, or if there is an
// error, instead it will return the zero value and the relevant error. An
// error will be returned if the given shares do not have valid indices as per
// the index set that the Reconstructor was constructed with. Specifically, if
// any of the given shares have an index that is not in the Reconstructor's
// index set, an error will be returned. Additionally, an error will also be
// returned if any two of the shares have the same index.
//
// NOTE: This function does not have any knowledge of the reconstruction
// threshold k. This means that if this function is invoked with k' < k shares
// for some k-sharing, then no error will be returned but the return value will
// be incorrect.
//
// NOTE: This function does not implement any fault tolerance. That is, it is
// assumed that all of the shares given form part of a consistent sharing for
// the given index set. Incorrect values will be returned if any of the shares
// that are given are malicious (altered from their original value).
func (r *Reconstructor) Open(shares Shares) (secp256k1.Fn, error) {
	var secret secp256k1.Fn

	// If there are more shares than indices, then either there is a share with
	// an index not in the index set, or two shares have the same index. In
	// either case, an error should be returned.
	if len(shares) > len(r.indices) {
		return secret, fmt.Errorf(
			"too many shares: expected len(shares) <= %v, got len(shares) = %b",
			len(r.indices), len(shares),
		)
	}

	// Map the shares onto the corresponding indices in r.indices. That is,
	// once the following is completed, it will be the case that
	//		shares[i].Index == r.indices[r.indInts[i]]
	r.indInts = r.indInts[:len(shares)]
OUTER:
	for i, share := range shares {
		for j, ind := range r.indices {
			if share.IndexEq(&ind) {
				r.indInts[i] = j
				continue OUTER
			}
		}

		// If we get here, then it follows that the share did not have an index
		// that is in the index set, so we return a corresponding error.
		return secret, fmt.Errorf(
			"unexpected share index: share has index %v which is out of the index set",
			share.Index,
		)
	}

	// Check if any of the shares have the same index. This is incorrect input,
	// and so an error will be returned.
	for i := range r.seen {
		r.seen[i] = false
	}
	for _, ind := range r.indInts {
		if r.seen[ind] {
			return secret, fmt.Errorf(
				"shares must have distinct indices: two shares have index %v",
				r.indices[ind].Int(),
			)
		}
		r.seen[ind] = true
	}

	// We now build up a list that corresponds to indices not in the index set.
	// That is, we want that for every index i in r.indices that is not equal
	// to share.Index for any of the shares in the input shares, that
	// r.indices[r.complement[j]] == i for some j. In other words, r.complement
	// contains the list locations in r.indices that correspond to indices not
	// equal to share.Index for any of the shares.

	// To achieve this, we first fill r.complement with 0s and 1s, where a 1 at
	// index i represents that we want i in our final set.
	r.complement = r.complement[:cap(r.complement)]
	for i := range r.complement {
		r.complement[i] = 1
	}
	for _, ind := range r.indInts {
		r.complement[ind] = 0
	}

	// Now fill in the actual position values and compress the slice.
	var toggle int
	for i, j := 0, 0; i < len(r.indices); i++ {
		toggle = r.complement[i]
		r.complement[j] = toggle * i
		j += toggle
	}
	r.complement = r.complement[:len(r.indices)-len(shares)]

	// This is an altered form of Lagrange interpolation that aims to utilise
	// more precomputed data. It works as follows. In the product, instead of
	// ranging over every index in the shares, we use a precomputed value that
	// ranges over all indices, and then to adjust it for the given shares we
	// multiply this by  the inverse of the terms that should not be included
	// in the product. This allows us to compute all inverses, which is the
	// most expensive operation, in the precompute stage.
	var term, diff secp256k1.Fn
	for i, share := range shares {
		term = share.Value
		term.Mul(&term, &r.fullProd[r.indInts[i]])
		for _, j := range r.complement {
			diff.Negate(&r.indices[r.indInts[i]])
			diff.Add(&r.indices[j], &diff)
			term.Mul(&term, &diff)
			term.Mul(&term, &r.indInv[j])
		}
		secret.Add(&secret, &term)
	}

	return secret, nil
}

// CheckedOpen is a wrapper around Open that also checks if enough shares have
// been given for reconstruction, as determined by the given threshold k. If
// there are less than k shares given, an error is returned.
func (r *Reconstructor) CheckedOpen(shares Shares, k int) (secp256k1.Fn, error) {
	if len(shares) < k {
		return secp256k1.Fn{}, fmt.Errorf(
			"not enough shares for reconstruction: expected at least %v, got %v",
			k, len(shares),
		)
	}
	return r.Open(shares)
}
