package shamir

import (
	"fmt"

	"github.com/renproject/secp256k1-go"
)

// Shares represents a slice of Shamir shares
type Shares []Share

// Share represents a single share in a Shamir secret sharing scheme.
type Share struct {
	index secp256k1.Secp256k1N
	value secp256k1.Secp256k1N
}

// NewShare constructs a new Shamir share from an index and a value.
func NewShare(index secp256k1.Secp256k1N, value secp256k1.Secp256k1N) Share {
	return Share{index, value}
}

// Index returns a copy of the index of the share.
func (s *Share) Index() secp256k1.Secp256k1N {
	return s.index
}

// Value returns a copy of the value of the share.
func (s *Share) Value() secp256k1.Secp256k1N {
	return s.value
}

// IndexEq returns true if the index of the two shares are equal, and false
// otherwise.
func (s *Share) IndexEq(other *secp256k1.Secp256k1N) bool {
	return s.index.Eq(other)
}

// Add computes the addition of the two input shares and stores the result in
// the caller. Addition is defined by adding the values but leaving the index
// unchanged.
//
// Panics: Addition only makes sense when the two input shares have the same
// index. If they do not, this functino wil panic.
func (s *Share) Add(a, b *Share) {
	if !a.index.Eq(&b.index) {
		panic(fmt.Sprintf(
			"cannot add shares with different indices: lhs has index %v and rhs has index %v",
			a.index,
			b.index,
		))
	}

	s.index = a.index
	s.value.Add(&a.value, &b.value)
	s.value.Normalize()
}

// Scale multiplies the input share by a constant and then stores it in the
// caller. This is defined as multiplying the share value by the scale, and
// leaving the index unchanged.
func (s *Share) Scale(other *Share, scale *secp256k1.Secp256k1N) {
	s.index = other.index
	s.value.Mul(&other.value, scale)
	s.value.Normalize()
}

// A Sharer is responsible for creating Shamir sharings of secrets. A Sharer
// instance is bound to a specific set of indices; it can only create sharings
// of a secret for the set of players defined by these indices.
type Sharer struct {
	indices []secp256k1.Secp256k1N
	coeffs  []secp256k1.Secp256k1N
}

// NewSharer constructs a new Sharer object from the given set of indices.
func NewSharer(indices []secp256k1.Secp256k1N) Sharer {
	coeffs := make([]secp256k1.Secp256k1N, len(indices))
	return Sharer{indices, coeffs}
}

// Share creates Shamir shares for the given secret at the given threshold, and
// stores them in the given destination slice. In the returned Shares, there
// will be one share for each index in the indices that were used to construct
// the Sharer.
//
// Panics: This function will panic if the destination shares slice has a
// capacity less than n (the number of indices).
func (sharer *Sharer) Share(shares *Shares, secret secp256k1.Secp256k1N, k int) error {
	if k > len(sharer.indices) {
		return fmt.Errorf(
			"reconstruction threshold too large: expected k <= %v, got k = %v",
			len(sharer.indices), k,
		)
	}

	// Set coefficients
	sharer.setRandomCoeffs(secret, k)

	// Set shares
	*shares = (*shares)[:len(sharer.indices)]
	var eval secp256k1.Secp256k1N
	for i, ind := range sharer.indices {
		polyEval(&eval, &ind, sharer.coeffs)
		(*shares)[i].index = ind
		(*shares)[i].value = eval
	}

	return nil
}

// Sets the coefficients of the Sharer to represent a random degree k-1
// polynomial with constant term equal to the given secret.
func (sharer *Sharer) setRandomCoeffs(secret secp256k1.Secp256k1N, k int) {
	sharer.coeffs = sharer.coeffs[:k]
	sharer.coeffs[0] = secret
	for i := 1; i < k; i++ {
		sharer.coeffs[i] = secp256k1.RandomSecp256k1N()
	}
}

// Evaluates the polynomial defined by the given coefficients at the point x
// and stores the result in y. Modifies y, but leaves x and coeffs unchanged.
// Normalizes y, so this this is not neccesary to do manually after calling
// this function.
func polyEval(y, x *secp256k1.Secp256k1N, coeffs []secp256k1.Secp256k1N) {
	y.Set(&coeffs[len(coeffs)-1])
	for i := len(coeffs) - 2; i >= 0; i-- {
		y.Mul(y, x)
		y.Add(y, &coeffs[i])
	}
	y.Normalize()
}

// A Reconstructor is responsible for reconstructing shares into their
// corresponding secret. Each instance can only perform reconstructions for a
// given fixed set of indices.
type Reconstructor struct {
	indices    []secp256k1.Secp256k1N
	fullProd   []secp256k1.Secp256k1N
	indInv     []secp256k1.Secp256k1N
	indInts    []int
	seen       []bool
	complement []int
}

// NewReconstructor returns a new Reconstructor instance for the given indices.
func NewReconstructor(indices []secp256k1.Secp256k1N) Reconstructor {
	fullProd := make([]secp256k1.Secp256k1N, len(indices))
	indInv := make([]secp256k1.Secp256k1N, len(indices))
	indInts := make([]int, len(indices))
	seen := make([]bool, len(indices))
	complement := make([]int, len(indices))

	// Precopmuted data
	var neg, inv secp256k1.Secp256k1N
	for i := range indices {
		fullProd[i] = secp256k1.OneSecp256k1N()
		neg.Neg(&indices[i], 1)
		for j := range indices {
			if i == j {
				continue
			}

			inv.Add(&indices[j], &neg)
			inv.Inv(&inv)
			inv.Mul(&inv, &indices[j])

			fullProd[i].Mul(&fullProd[i], &inv)
		}
	}
	for i, ind := range indices {
		indInv[i].Inv(&ind)
	}

	return Reconstructor{indices, fullProd, indInv, indInts, seen, complement}
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
func (r *Reconstructor) Open(shares Shares) (secp256k1.Secp256k1N, error) {
	var secret secp256k1.Secp256k1N

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
	//		shares[i].Index() == r.indices[r.indInts[i]]
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
			share.Index(),
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
	// to share.Index() for any of the shares in the input shares, that
	// r.indices[r.complement[j]] == i for some j. In other words, r.complement
	// contains the list locations in r.indices that correspond to indices not
	// equal to share.Index() for any of the shares.

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

	// This is an altered for of Lagrange interpolation that aims to utilise
	// more precomputed data. It works as follows. In the product, instead of
	// ranging over every index in the shares, we use a precomputed value that
	// ranges over all indices, and then to adjust it for the given shares we
	// multiply this by  the inverse of the terms that should not be included
	// in the product. This allows us to compute all inverses, which is the
	// most expensive operation, in the precompute stage.
	var term, diff secp256k1.Secp256k1N
	for i, share := range shares {
		term = share.Value()
		term.Mul(&term, &r.fullProd[r.indInts[i]])
		for _, j := range r.complement {
			diff.Neg(&r.indices[r.indInts[i]], 1)
			diff.Add(&r.indices[j], &diff)
			term.Mul(&term, &diff)
			term.Mul(&term, &r.indInv[j])
		}
		secret.Add(&secret, &term)
	}
	secret.Normalize()

	return secret, nil
}

// CheckedOpen is a wrapper around Open that also checks if enough shares have
// been given for reconstruction, as determined by the given threshold k. If
// there are less than k shares given, an error is returned.
func (r *Reconstructor) CheckedOpen(shares Shares, k int) (secp256k1.Secp256k1N, error) {
	if len(shares) < k {
		return secp256k1.ZeroSecp256k1N(), fmt.Errorf(
			"not enough shares for reconstruction: expected at least %v, got %v",
			k, len(shares),
		)
	}
	return r.Open(shares)
}
