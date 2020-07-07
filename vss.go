package shamir

import (
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"
)

// VShareSize is the size of a verifiable share in bytes.
const VShareSize = ShareSize + secp256k1.FnSize

// VerifiableShares is a alias for a slice of VerifiableShare(s).
type VerifiableShares []VerifiableShare

// SizeHint implements the surge.SizeHinter interface.
func (vshares VerifiableShares) SizeHint() int { return surge.SizeHintU32 + VShareSize*len(vshares) }

// Marshal implements the surge.Marshaler interface.
func (vshares VerifiableShares) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalU32(uint32(len(vshares)), buf, rem)
	if err != nil {
		return buf, rem, err
	}

	for i := range vshares {
		buf, rem, err = vshares[i].Marshal(buf, rem)
		if err != nil {
			return buf, rem, err
		}
	}

	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (vshares *VerifiableShares) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	var l uint32
	buf, rem, err := surge.UnmarshalLen(&l, VShareSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}

	if *vshares == nil {
		*vshares = make(VerifiableShares, 0)
	}

	*vshares = (*vshares)[:0]
	for i := uint32(0); i < l; i++ {
		*vshares = append(*vshares, VerifiableShare{})
		buf, rem, err = (*vshares)[i].Unmarshal(buf, rem)
		if err != nil {
			return buf, rem, err
		}
	}

	return buf, rem, nil
}

// Shares returns the underlying (unverified) shares.
func (vshares VerifiableShares) Shares() Shares {
	shares := make(Shares, len(vshares))

	for i, vshare := range vshares {
		shares[i] = vshare.Share()
	}

	return shares
}

// A VerifiableShare is a Share but with additional information that allows it
// to be verified as correct for a given commitment to a sharing.
type VerifiableShare struct {
	share Share
	r     secp256k1.Fn
}

// Generate implements the quick.Generator interface.
func (vs VerifiableShare) Generate(_ *rand.Rand, _ int) reflect.Value {
	return reflect.ValueOf(
		NewVerifiableShare(
			NewShare(secp256k1.RandomFn(), secp256k1.RandomFn()),
			secp256k1.RandomFn(),
		),
	)
}

// NewVerifiableShare constructs a new VerifiableShare from the given Share and
// decommitment value. This function allows the manual construction of a
// VerifiableShare, and should be only used if such fine grained control is
// needed. In general, shares should be constructed by using a VSSharer.
func NewVerifiableShare(share Share, r secp256k1.Fn) VerifiableShare {
	return VerifiableShare{share, r}
}

// Eq returns true if the two verifiable shares are equal, and false otherwise.
func (vs *VerifiableShare) Eq(other *VerifiableShare) bool {
	return vs.share.Eq(&other.share) && vs.r.Eq(&other.r)
}

// SizeHint implements the surge.SizeHinter interface.
func (vs VerifiableShare) SizeHint() int { return vs.share.SizeHint() + vs.r.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (vs VerifiableShare) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := vs.share.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	buf, rem, err = vs.r.Marshal(buf, rem)
	return buf, rem, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (vs *VerifiableShare) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := vs.share.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	return vs.r.Unmarshal(buf, rem)
}

// Share returns the underlying Shamir share of the verifiable share.
func (vs *VerifiableShare) Share() Share {
	return vs.share
}

// Decommitment returns the index of the verifiable share.
func (vs *VerifiableShare) Decommitment() secp256k1.Fn {
	return vs.r
}

// Add computes the addition of the two input shares and stores the result in
// the caller. This is defined as adding the respective normal (unverifiable)
// shares and adding the respective decommitment values. In general, the
// resulting share will be a share with secret value equal to the sum of the
// two secrets corresponding to the (respective sharings of the) input shares.
func (vs *VerifiableShare) Add(a, b *VerifiableShare) {
	vs.share.Add(&a.share, &b.share)
	vs.r.Add(&a.r, &b.r)
}

// Scale computes the scaling of the input share by given scale factor and
// stores the result in the caller. This is defined as scaling the normal
// (unverifiable) share by the scaling factor and multiplying the decommitment
// value also by the scaling factor. In general, the resulting share will be a
// share with secret value equal to the scale factor multiplied by the secret
// corresponding to the (sharing of the) input share.
func (vs *VerifiableShare) Scale(other *VerifiableShare, scale *secp256k1.Fn) {
	vs.share.Scale(&other.share, scale)
	vs.r.Mul(&other.r, scale)
}

// A Commitment is used to verify that a sharing has been performed correctly.
type Commitment []secp256k1.Point

// Generate implements the quick.Generator interface.
func (c Commitment) Generate(rand *rand.Rand, size int) reflect.Value {
	com := make(Commitment, rand.Intn(size))
	for i := range com {
		com[i] = secp256k1.RandomPoint()
	}
	return reflect.ValueOf(com)
}

// Eq returns true if the two commitments are equal (each curve point is
// equal), and false otherwise.
func (c Commitment) Eq(other Commitment) bool {
	if len(c) != len(other) {
		return false
	}

	for i := range c {
		if !c[i].Eq(&other[i]) {
			return false
		}
	}

	return true
}

// Append a point to the commitment.
func (c *Commitment) Append(p secp256k1.Point) {
	*c = append(*c, p)
}

// Len returns the number of curve points in the commitment. This is equal to
// the reconstruction threshold of the associated verifiable sharing.
func (c Commitment) Len() int {
	return len(c)
}

// Set the calling commitment to be equal to the given commitment.
func (c *Commitment) Set(other Commitment) {
	if len(*c) < len(other) {
		*c = NewCommitmentWithCapacity(len(other))
	}

	*c = (*c)[:len(other)]
	for i := range *c {
		(*c)[i] = other[i]
	}
}

// SizeHint implements the surge.SizeHinter interface.
func (c Commitment) SizeHint() int {
	return surge.SizeHintU32 + secp256k1.PointSizeMarshalled*len(c)
}

// Marshal implements the surge.Marshaler interface.
func (c Commitment) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalU32(uint32(len(c)), buf, rem)
	if err != nil {
		return buf, rem, err
	}

	for i := range c {
		buf, rem, err = c[i].Marshal(buf, rem)
		if err != nil {
			return buf, rem, err
		}
	}

	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (c *Commitment) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	var l uint32
	buf, rem, err := surge.UnmarshalLen(&l, secp256k1.PointSize, buf, rem)
	if err != nil {
		return buf, rem, err
	}

	if *c == nil {
		*c = make([]secp256k1.Point, 0)
	}

	*c = (*c)[:0]
	for i := uint32(0); i < l; i++ {
		*c = append(*c, secp256k1.Point{})
		buf, rem, err = (*c)[i].Unmarshal(buf, rem)
		if err != nil {
			return buf, rem, err
		}
	}
	return buf, rem, nil
}

// NewCommitmentWithCapacity creates a new Commitment with the given capacity.
// This capacity represents the maximum reconstruction threshold, k, that this
// commitment can be used for.
func NewCommitmentWithCapacity(k int) Commitment {
	return make(Commitment, 0, k)
}

// Add takes two input commitments and stores in the caller the commitment that
// represents the addition of these two commitments. That is, the new
// commitment can be used to verify the correctness of the sharing defined by
// adding the two corresponding sharings for the input commitments. For
// example, if `a_i` is a valid share for the commitment `a`, and `b_i` is a
// valid share for the commitment `b`, then `a_i + b_i` will be a valid share
// for the newly constructed commitment.
//
// Panics: If the destination commitment does not have capacity at least as big
// as the greater of the capacities of the two inputs, then this function will
// panic.
func (c *Commitment) Add(a, b Commitment) {
	var smaller, larger []secp256k1.Point
	if len(a) > len(b) {
		smaller, larger = b, a
	} else {
		smaller, larger = a, b
	}

	*c = (*c)[:len(larger)]
	for i := range smaller {
		(*c)[i].Add(&smaller[i], &larger[i])
	}
	copy((*c)[len(smaller):], larger[len(smaller):])
}

// Scale takes an input commitment and stores in the caller the commitment that
// represents the scaled input commitment. That is, the new commitment can be
// used to verify the correctness of the sharing defined by scaling the
// original sharing. For example, if `a_i` is a valid share for the commitment
// `other`, then `scale * a_i` will be a valid sharing for the newly
// constructed commitment.
//
// Panics: If the destination commitment does not have capacity at least as big
// as the input commitment, then this function will panic.
func (c *Commitment) Scale(other Commitment, scale *secp256k1.Fn) {
	*c = (*c)[:len(other)]
	for i := range *c {
		(*c)[i].Scale(&other[i], scale)
	}
}

// Evaluates the sharing polynomial at the given index "in the exponent".
func (c *Commitment) evaluate(eval *secp256k1.Point, index *secp256k1.Fn) {
	*eval = (*c)[len(*c)-1]
	for i := len(*c) - 2; i >= 0; i-- {
		eval.Scale(eval, index)
		eval.Add(eval, &(*c)[i])
	}
}

// A VSSChecker is capable of checking that a given share is valid for a given
// commitment to a sharing. Each instance of this type corresponds to a
// different group element h for the Pedersen commitment scheme, and as such
// can by used for any verifiable sharings using this pedersen commitment
// scheme, but cannot be used for different choices of h once constructed.
//
// NOTE: This struct is not safe for concurrent use.
type VSSChecker struct {
	h secp256k1.Point

	// Cached vairables
	eval, gPow, hPow secp256k1.Point
}

// Generate implements the quick.Generator interface.
func (checker VSSChecker) Generate(_ *rand.Rand, _ int) reflect.Value {
	return reflect.ValueOf(NewVSSChecker(secp256k1.RandomPoint()))
}

// SizeHint implements the surge.SizeHinter interface.
func (checker VSSChecker) SizeHint() int { return checker.h.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (checker VSSChecker) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return checker.h.Marshal(buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (checker *VSSChecker) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := checker.h.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}
	return buf, rem, nil
}

// NewVSSChecker constructs a new VSS checking instance for the given Pedersen
// commitment scheme parameter h. The other generator g is always chosen to be
// the canonical base point for the secp256k1 curve.
func NewVSSChecker(h secp256k1.Point) VSSChecker {
	eval, gPow, hPow := secp256k1.Point{}, secp256k1.Point{}, secp256k1.Point{}
	return VSSChecker{h, eval, gPow, hPow}
}

// IsValid returns true when the given verifiable share is valid with regard to
// the given commitment, and false otherwise.
func (checker *VSSChecker) IsValid(c *Commitment, vshare *VerifiableShare) bool {
	checker.gPow.BaseExp(&vshare.share.value)
	checker.hPow.Scale(&checker.h, &vshare.r)
	checker.gPow.Add(&checker.gPow, &checker.hPow)

	c.evaluate(&checker.eval, &vshare.share.index)
	return checker.gPow.Eq(&checker.eval)
}

// A VSSharer is capable of creating a verifiable sharing of a secret, which is
// just a normal Shamir sharing but with the addition of a commitment which is
// a collection of commitments to each of the coefficients of the sharing.
//
// NOTE: This struct is not safe for concurrent use.
type VSSharer struct {
	sharer Sharer
	h      secp256k1.Point

	// Cached variables
	shares Shares
	hPow   secp256k1.Point
}

// Generate implements the quick.Generator interface.
func (s VSSharer) Generate(rand *rand.Rand, size int) reflect.Value {
	indices := make([]secp256k1.Fn, rand.Intn(size))
	for i := range indices {
		indices[i] = secp256k1.RandomFn()
	}
	return reflect.ValueOf(NewVSSharer(indices, secp256k1.RandomPoint()))
}

// SizeHint implements the surge.SizeHinter interface.
func (s VSSharer) SizeHint() int { return s.sharer.SizeHint() + s.h.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (s VSSharer) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := s.sharer.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	buf, rem, err = s.h.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (s *VSSharer) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := s.sharer.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	buf, rem, err = s.h.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	s.shares = make(Shares, len(s.sharer.indices))
	return buf, rem, nil
}

// N returns the number of players associated with this VSSharer instance. This
// is equal to the number of indices it was constructed with.
func (s *VSSharer) N() int {
	return s.sharer.N()
}

// NewVSSharer constructs a new VSSharer from the given set of indices.
func NewVSSharer(indices []secp256k1.Fn, h secp256k1.Point) VSSharer {
	sharer := NewSharer(indices)
	shares := make(Shares, len(indices))
	hPow := secp256k1.Point{}
	return VSSharer{sharer, h, shares, hPow}
}

// Share creates verifiable Shamir shares for the given secret at the given
// threshold, and stores the shares and the commitment in the given
// destinations. In the returned Shares, there will be one share for each index
// in the indices that were used to construct the Sharer.
//
// Panics: This function will panic if the destination shares slice has a
// capacity less than n (the number of indices), or if the destination
// commitment has a capacity less than k.
func (s *VSSharer) Share(vshares *VerifiableShares, c *Commitment, secret secp256k1.Fn, k int) error {
	err := s.sharer.Share(&s.shares, secret, k)
	if err != nil {
		return err
	}

	// At this point, the sharer should still have the randomly picked
	// coefficients in its cache, which we need to use for the commitment.
	*c = (*c)[:k]
	for i, coeff := range s.sharer.coeffs {
		(*c)[i].BaseExp(&coeff)
	}

	s.sharer.setRandomCoeffs(secp256k1.RandomFn(), k)
	for i, ind := range s.sharer.indices {
		(*vshares)[i].share = s.shares[i]
		polyEval(&(*vshares)[i].r, &ind, s.sharer.coeffs)
	}

	// Finish the computation of the commitments
	for i, coeff := range s.sharer.coeffs {
		s.hPow.Scale(&s.h, &coeff)
		(*c)[i].Add(&(*c)[i], &s.hPow)
	}

	return nil
}
