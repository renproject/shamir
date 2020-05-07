package shamir

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/surge"
)

// FnSizeBytes is the number of bytes in the secp256k1.Secp256k1N type.
const FnSizeBytes = 32

// ShareSizeBytes is the number of bytes in a share.
const ShareSizeBytes = 64

// Shares represents a slice of Shamir shares
type Shares []Share

// SizeHint implements the surge.SizeHinter interface.
func (shares Shares) SizeHint() int { return 4 + ShareSizeBytes*len(shares) }

// Marshal implements the surge.Marshaler interface.
func (shares Shares) Marshal(w io.Writer, m int) (int, error) {
	if m < 4 {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [4]byte

	binary.BigEndian.PutUint32(bs[:], uint32(len(shares)))
	n, err := w.Write(bs[:])
	m -= n
	if err != nil {
		return m, err
	}

	for i := range shares {
		m, err = shares[i].Marshal(w, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (shares *Shares) Unmarshal(r io.Reader, m int) (int, error) {
	if m < 4 {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [4]byte

	// Slice length.
	n, err := io.ReadFull(r, bs[:])
	m -= n
	if err != nil {
		return m, err
	}
	l := binary.BigEndian.Uint32(bs[:])
	// Casting m (signed) to an unsigned int is safe here. This is because it
	// is guaranteed to be positive: we check at the start of the function that
	// m >= 4, and then only subtract n which satisfies n <= 4.
	if uint32(m) < l*ShareSizeBytes {
		return m, surge.ErrMaxBytesExceeded
	}

	*shares = (*shares)[:0]
	for i := uint32(0); i < l; i++ {
		*shares = append(*shares, Share{})
		m, err = (*shares)[i].Unmarshal(r, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

// Share represents a single share in a Shamir secret sharing scheme.
type Share struct {
	index secp256k1.Secp256k1N
	value secp256k1.Secp256k1N
}

// NewShare constructs a new Shamir share from an index and a value.
func NewShare(index secp256k1.Secp256k1N, value secp256k1.Secp256k1N) Share {
	return Share{index, value}
}

// GetBytes serialises the share into bytes and writes these bytes into the
// given destination slice. A serialises to 64 bytes.
//
// Panics: If the destination slice has length less than 64, this function will
// panic.
func (s *Share) GetBytes(dst []byte) {
	// Byte format:
	//
	// - First 32 bytes: index in big endian format.
	// - Last 32 bytes: value in big endian format.

	s.index.GetB32(dst[:32])
	s.value.GetB32(dst[32:])
}

// SetBytes sets the caller from the given bytes. The format of these bytes is
// that determined by the GetBytes method.
func (s *Share) SetBytes(bs []byte) {
	s.index.SetB32(bs[:32])
	s.value.SetB32(bs[32:])
}

// Eq returns true if the two shares are equal, and false otherwise.
func (s *Share) Eq(other *Share) bool {
	return s.index.Eq(&other.index) && s.value.Eq(&other.value)
}

// SizeHint implements the surge.SizeHinter interface.
func (s *Share) SizeHint() int { return s.index.SizeHint() + s.value.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (s *Share) Marshal(w io.Writer, m int) (int, error) {
	m, err := s.index.Marshal(w, m)
	if err != nil {
		return m, err
	}

	m, err = s.value.Marshal(w, m)
	return m, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (s *Share) Unmarshal(r io.Reader, m int) (int, error) {
	m, err := s.index.Unmarshal(r, m)
	if err != nil {
		return m, err
	}

	m, err = s.value.Unmarshal(r, m)
	return m, err
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
//
// NOTE: This struct is not safe for concurrent use.
type Sharer struct {
	indices []secp256k1.Secp256k1N
	coeffs  []secp256k1.Secp256k1N
}

// SizeHint implements the surge.SizeHinter interface.
func (sharer *Sharer) SizeHint() int { return 4 + len(sharer.indices)*FnSizeBytes }

// Marshal implements the surge.Marshaler interface.
func (sharer *Sharer) Marshal(w io.Writer, m int) (int, error) {
	return marshalFromIndices(sharer.indices, w, m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (sharer *Sharer) Unmarshal(r io.Reader, m int) (int, error) {
	var indices []secp256k1.Secp256k1N
	var err error

	m, err = unmarshalToIndices(&indices, r, m)
	if err != nil {
		return m, err
	}

	*sharer = NewSharer(indices)

	return m, nil
}

func marshalFromIndices(indices []secp256k1.Secp256k1N, w io.Writer, m int) (int, error) {
	if m < 4 {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [FnSizeBytes]byte

	binary.BigEndian.PutUint32(bs[:4], uint32(len(indices)))
	n, err := w.Write(bs[:4])
	m -= n
	if err != nil {
		return m, err
	}

	for i := range indices {
		m, err = indices[i].Marshal(w, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

func unmarshalToIndices(dst *[]secp256k1.Secp256k1N, r io.Reader, m int) (int, error) {
	if m < 4 {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [4]byte

	// Slice length.
	n, err := io.ReadFull(r, bs[:])
	m -= n
	if err != nil {
		return m, err
	}
	l := binary.BigEndian.Uint32(bs[:])
	// Casting m (signed) to an unsigned int is safe here. This is because it
	// is guaranteed to be positive: we check at the start of the function that
	// m >= 4, and then only subtract n which satisfies n <= 4.
	if uint32(m) < l*FnSizeBytes {
		return m, surge.ErrMaxBytesExceeded
	}

	*dst = (*dst)[:0]
	for i := uint32(0); i < l; i++ {
		*dst = append(*dst, secp256k1.Secp256k1N{})
		m, err = (*dst)[i].Unmarshal(r, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

// NewSharer constructs a new Sharer object from the given set of indices.
func NewSharer(indices []secp256k1.Secp256k1N) Sharer {
	copiedIndices := make([]secp256k1.Secp256k1N, len(indices))
	copy(copiedIndices, indices)
	coeffs := make([]secp256k1.Secp256k1N, len(indices))
	return Sharer{indices: copiedIndices, coeffs: coeffs}
}

// Share creates Shamir shares for the given secret at the given threshold, and
// stores them in the given destination slice. In the returned Shares, there
// will be one share for each index in the indices that were used to construct
// the Sharer. If k is larger than the number of indices, in which case it
// would be impossible to reconstruct the secret, an error is returned.
//
// Panics: This function will panic if the destination shares slice has a
// capacity less than n (the number of indices).
func (sharer *Sharer) Share(dst *Shares, secret secp256k1.Secp256k1N, k int) error {
	if k > len(sharer.indices) {
		return fmt.Errorf(
			"reconstruction threshold too large: expected k <= %v, got k = %v",
			len(sharer.indices), k,
		)
	}

	// Set coefficients
	sharer.setRandomCoeffs(secret, k)

	// Set shares
	// NOTE: This panics if the destination slice does not have the required
	// capacity.
	*dst = (*dst)[:len(sharer.indices)]
	var eval secp256k1.Secp256k1N
	for i, ind := range sharer.indices {
		polyEval(&eval, &ind, sharer.coeffs)
		(*dst)[i].index = ind
		(*dst)[i].value = eval
	}

	return nil
}

// Sets the coefficients of the Sharer to represent a random degree k-1
// polynomial with constant term equal to the given secret.
//
// Panics: This function will panic if k is greater than len(sharer.coeffs).
func (sharer *Sharer) setRandomCoeffs(secret secp256k1.Secp256k1N, k int) {
	sharer.coeffs = sharer.coeffs[:k]
	sharer.coeffs[0] = secret

	// NOTE: If k is greater than len(sharer.coeffs), then this loop will panic
	// when i > len(sharer.coeffs).
	for i := 1; i < k; i++ {
		sharer.coeffs[i] = secp256k1.RandomSecp256k1N()
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
func polyEval(y, x *secp256k1.Secp256k1N, coeffs []secp256k1.Secp256k1N) {
	// NOTE: This will panic if len(coeffs) is less than 1 or if coeffs is nil.
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
//
// NOTE: This struct is not safe for concurrent use.
type Reconstructor struct {
	indices    []secp256k1.Secp256k1N
	fullProd   []secp256k1.Secp256k1N
	indInv     []secp256k1.Secp256k1N
	indInts    []int
	seen       []bool
	complement []int
}

// SizeHint implements the surge.SizeHinter interface.
func (r *Reconstructor) SizeHint() int { return 4 + len(r.indices)*FnSizeBytes }

// Marshal implements the surge.Marshaler interface.
func (r *Reconstructor) Marshal(w io.Writer, m int) (int, error) {
	return marshalFromIndices(r.indices, w, m)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (r *Reconstructor) Unmarshal(reader io.Reader, m int) (int, error) {
	var indices []secp256k1.Secp256k1N
	var err error

	m, err = unmarshalToIndices(&indices, reader, m)
	if err != nil {
		return m, err
	}

	*r = NewReconstructor(indices)

	return m, nil
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
		neg.Normalize()
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

	// This is an altered form of Lagrange interpolation that aims to utilise
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
