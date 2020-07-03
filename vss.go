package shamir

import (
	"encoding/binary"

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
	buf, rem, err := surge.UnmarshalU32(&l, buf, rem)
	if err != nil {
		return buf, rem, err
	}

	// TODO: Consider overflow.
	c := l * uint32(VShareSize)
	if uint32(len(buf)) < c || uint32(rem) < c {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
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

// NewVerifiableShare constructs a new VerifiableShare from the given Share and
// decommitment value. This function allows the manual construction of a
// VerifiableShare, and should be only used if such fine grained control is
// needed. In general, shares should be constructed by using a VSSharer.
func NewVerifiableShare(share Share, r secp256k1.Fn) VerifiableShare {
	return VerifiableShare{share, r}
}

// PutBytes serialises the verifiable share into bytes and writes these bytes
// into the given destination slice. A verifiable serialises to 96 bytes.
//
// Panics: If the destination slice has length less than 96, this function will
// panic.
func (vs *VerifiableShare) PutBytes(dst []byte) {
	// Byte format:
	//
	// - First 64 bytes: serialised Shamir share.
	// - Last 32 bytes: decommitment value in big endian format.

	vs.share.PutBytes(dst[:ShareSize])
	vs.r.PutB32(dst[ShareSize:])
}

// SetBytes sets the caller from the given bytes. The format of these bytes is
// that determined by the PutBytes method.
func (vs *VerifiableShare) SetBytes(bs []byte) {
	vs.share.SetBytes(bs[:ShareSize])
	vs.r.SetB32(bs[ShareSize:])
}

// Eq returns true if the two verifiable shares are equal, and false otherwise.
func (vs *VerifiableShare) Eq(other *VerifiableShare) bool {
	return vs.share.Eq(&other.share) && vs.r.Eq(&other.r)
}

// SizeHint implements the surge.SizeHinter interface.
func (vs *VerifiableShare) SizeHint() int { return vs.share.SizeHint() + vs.r.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (vs *VerifiableShare) Marshal(buf []byte, rem int) ([]byte, int, error) {
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
type Commitment struct {
	// Curve points that represent Pedersen commitments to each of the
	// coefficients.  Index i corresponds to coefficient c_i.
	points []secp256k1.Point
}

// Eq returns true if the two commitments are equal (each curve point is
// equal), and false otherwise.
func (c *Commitment) Eq(other *Commitment) bool {
	if len(c.points) != len(other.points) {
		return false
	}

	for i := range c.points {
		if !c.points[i].Eq(&other.points[i]) {
			return false
		}
	}

	return true
}

// Len returns the number of curve points in the commitment. This is equal to
// the reconstruction threshold of the associated verifiable sharing.
func (c *Commitment) Len() int {
	return len(c.points)
}

// Set the calling commitment to be equal to the given commitment.
func (c *Commitment) Set(other Commitment) {
	if len(c.points) < len(other.points) {
		*c = NewCommitmentWithCapacity(len(other.points))
	}

	c.points = c.points[:len(other.points)]
	for i := range c.points {
		c.points[i] = other.points[i]
	}
}

// GetPoint returns the elliptic curve point at the given index of the commitment
func (c Commitment) GetPoint(index int) secp256k1.Point {
	return c.points[index]
}

// AppendPoint appends an elliptic curve point to the given commitment
func (c *Commitment) AppendPoint(point secp256k1.Point) {
	c.points = append(c.points, point)
}

// PutBytes serialises the commitment into bytes and writes these bytes into
// the given destination slice.
//
// Panics: If the destination slice has length smaller than required, this
// function may panic. The exact length requirement can be obtained from the
// SizeHint method.
func (c *Commitment) PutBytes(dst []byte) {
	// Byte format:
	//
	// - First 4 bytes: slice length in big endian as a uint32.
	// - Remaining bytes: successive groups of 64 bytes containing the
	// serialised curve points.

	binary.BigEndian.PutUint32(dst[:4], uint32(len(c.points)))
	for i, p := range c.points {
		p.PutBytes(dst[secp256k1.PointSize*i+4:])
	}
}

// SetBytes sets the caller from the given bytes. The format of these bytes is
// that determined by the PutBytes method.
func (c *Commitment) SetBytes(bs []byte) {
	nPoints := int(binary.BigEndian.Uint32(bs[:4]))
	c.points = c.points[:nPoints]
	for i := 0; i < nPoints; i++ {
		c.points[i].SetBytes(bs[secp256k1.PointSize*i+4:])
	}
}

// SizeHint implements the surge.SizeHinter interface.
func (c Commitment) SizeHint() int { return secp256k1.PointSize*len(c.points) + 4 }

// Marshal implements the surge.Marshaler interface.
func (c Commitment) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := surge.MarshalU32(uint32(len(c.points)), buf, rem)
	if err != nil {
		return buf, rem, err
	}

	for i := range c.points {
		buf, rem, err = c.points[i].Marshal(buf, rem)
		if err != nil {
			return buf, rem, err
		}
	}

	return buf, rem, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (c *Commitment) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	var l uint32
	buf, rem, err := surge.UnmarshalU32(&l, buf, rem)
	if err != nil {
		return buf, rem, err
	}

	// TODO: Consider overflow.
	lim := l * uint32(secp256k1.PointSize)
	if uint32(len(buf)) < lim || uint32(rem) < lim {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}

	c.points = c.points[:0]
	for i := uint32(0); i < l; i++ {
		c.points = append(c.points, secp256k1.Point{})
		buf, rem, err = c.points[i].Unmarshal(buf, rem)
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
	points := make([]secp256k1.Point, k)
	for i := range points {
		points[i] = secp256k1.Point{}
	}
	points = points[:0]
	return Commitment{points}
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
func (c *Commitment) Add(a, b *Commitment) {
	var smaller, larger []secp256k1.Point
	if len(a.points) > len(b.points) {
		smaller, larger = b.points, a.points
	} else {
		smaller, larger = a.points, b.points
	}

	c.points = c.points[:len(larger)]
	for i := range smaller {
		c.points[i].Add(&smaller[i], &larger[i])
	}
	copy(c.points[len(smaller):], larger[len(smaller):])
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
func (c *Commitment) Scale(other *Commitment, scale *secp256k1.Fn) {
	c.points = c.points[:len(other.points)]
	for i := range c.points {
		c.points[i].Scale(&other.points[i], scale)
	}
}

// Evaluates the sharing polynomial at the given index "in the exponent".
func (c *Commitment) evaluate(eval *secp256k1.Point, index *secp256k1.Fn) {
	*eval = c.points[len(c.points)-1]
	for i := len(c.points) - 2; i >= 0; i-- {
		eval.Scale(eval, index)
		eval.Add(eval, &c.points[i])
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

// SizeHint implements the surge.SizeHinter interface.
func (checker *VSSChecker) SizeHint() int { return checker.h.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (checker *VSSChecker) Marshal(buf []byte, rem int) ([]byte, int, error) {
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

// SizeHint implements the surge.SizeHinter interface.
func (s *VSSharer) SizeHint() int { return s.sharer.SizeHint() + s.h.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (s *VSSharer) Marshal(buf []byte, rem int) ([]byte, int, error) {
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
	c.points = c.points[:k]
	for i, coeff := range s.sharer.coeffs {
		c.points[i].BaseExp(&coeff)
	}

	s.sharer.setRandomCoeffs(secp256k1.RandomFn(), k)
	for i, ind := range s.sharer.indices {
		(*vshares)[i].share = s.shares[i]
		polyEval(&(*vshares)[i].r, &ind, s.sharer.coeffs)
	}

	// Finish the computation of the commitments
	for i, coeff := range s.sharer.coeffs {
		s.hPow.Scale(&s.h, &coeff)
		c.points[i].Add(&c.points[i], &s.hPow)
	}

	return nil
}
