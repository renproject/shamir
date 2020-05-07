package shamir

import (
	"encoding/binary"
	"io"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir/curve"
	"github.com/renproject/surge"
)

// VShareSizeBytes is the size of a verifiable share in bytes.
const VShareSizeBytes = ShareSizeBytes + FnSizeBytes

// VerifiableShares is a alias for a slice of VerifiableShare(s).
type VerifiableShares []VerifiableShare

// SizeHint implements the surge.SizeHinter interface.
func (vshares VerifiableShares) SizeHint() int { return 4 + VShareSizeBytes*len(vshares) }

// Marshal implements the surge.Marshaler interface.
func (vshares VerifiableShares) Marshal(w io.Writer, m int) (int, error) {
	if m < 4 {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [4]byte

	binary.BigEndian.PutUint32(bs[:], uint32(len(vshares)))
	n, err := w.Write(bs[:])
	m -= n
	if err != nil {
		return m, err
	}

	for i := range vshares {
		m, err = vshares[i].Marshal(w, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (vshares *VerifiableShares) Unmarshal(r io.Reader, m int) (int, error) {
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
	if uint32(m) < l*VShareSizeBytes {
		return m, surge.ErrMaxBytesExceeded
	}

	*vshares = (*vshares)[:0]
	for i := uint32(0); i < l; i++ {
		*vshares = append(*vshares, VerifiableShare{})
		m, err = (*vshares)[i].Unmarshal(r, m)
		if err != nil {
			return m, err
		}
	}

	return m, nil
}

// A VerifiableShare is a Share but with additional information that allows it
// to be verified as correct for a given commitment to a sharing.
type VerifiableShare struct {
	share Share
	r     secp256k1.Secp256k1N
}

// NewVerifiableShare constructs a new VerifiableShare from the given Share and
// decommitment value. This function allows the manual construction of a
// VerifiableShare, and should be only used if such fine grained control is
// needed. In general, shares should be constructed by using a VSSharer.
func NewVerifiableShare(share Share, r secp256k1.Secp256k1N) VerifiableShare {
	return VerifiableShare{share, r}
}

// GetBytes serialises the verifiable share into bytes and writes these bytes
// into the given destination slice. A verifiable serialises to 96 bytes.
//
// Panics: If the destination slice has length less than 96, this function will
// panic.
func (vs *VerifiableShare) GetBytes(dst []byte) {
	// Byte format:
	//
	// - First 64 bytes: serialised Shamir share.
	// - Last 32 bytes: decommitment value in big endian format.

	vs.share.GetBytes(dst[:ShareSizeBytes])
	vs.r.GetB32(dst[ShareSizeBytes:])
}

// SetBytes sets the caller from the given bytes. The format of these bytes is
// that determined by the GetBytes method.
func (vs *VerifiableShare) SetBytes(bs []byte) {
	vs.share.SetBytes(bs[:ShareSizeBytes])
	vs.r.SetB32(bs[ShareSizeBytes:])
}

// Eq returns true if the two verifiable shares are equal, and false otherwise.
func (vs *VerifiableShare) Eq(other *VerifiableShare) bool {
	return vs.share.Eq(&other.share) && vs.r.Eq(&other.r)
}

// SizeHint implements the surge.SizeHinter interface.
func (vs *VerifiableShare) SizeHint() int { return vs.share.SizeHint() + vs.r.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (vs *VerifiableShare) Marshal(w io.Writer, m int) (int, error) {
	m, err := vs.share.Marshal(w, m)
	if err != nil {
		return m, err
	}

	m, err = vs.r.Marshal(w, m)
	return m, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (vs *VerifiableShare) Unmarshal(r io.Reader, m int) (int, error) {
	if m < vs.SizeHint() {
		return m, surge.ErrMaxBytesExceeded
	}

	m, err := vs.share.Unmarshal(r, m)
	if err != nil {
		return m, err
	}

	m, err = vs.r.Unmarshal(r, m)
	return m, err
}

// Share returns the underlying Shamir share of the verifiable share.
func (vs *VerifiableShare) Share() Share {
	return vs.share
}

// Decommitment returns the index of the verifiable share.
func (vs *VerifiableShare) Decommitment() secp256k1.Secp256k1N {
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
	vs.r.Normalize()
}

// Scale computes the scaling of the input share by given scale factor and
// stores the result in the caller. This is defined as scaling the normal
// (unverifiable) share by the scaling factor and multiplying the decommitment
// value also by the scaling factor. In general, the resulting share will be a
// share with secret value equal to the scale factor multiplied by the secret
// corresponding to the (sharing of the) input share.
func (vs *VerifiableShare) Scale(other *VerifiableShare, scale *secp256k1.Secp256k1N) {
	vs.share.Scale(&other.share, scale)
	vs.r.Mul(&other.r, scale)
	vs.r.Normalize()
}

// A Commitment is used to verify that a sharing has been performed correctly.
type Commitment struct {
	// Curve points that represent Pedersen commitments to each of the
	// coefficients.  Index i corresponds to coefficient c_i.
	points []curve.Point
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

// GetBytes serialises the commitment into bytes and writes these bytes into
// the given destination slice.
//
// Panics: If the destination slice has length smaller than required, this
// function may panic. The exact length requirement can be obtained from the
// SizeHint method.
func (c *Commitment) GetBytes(dst []byte) {
	// Byte format:
	//
	// - First 4 bytes: slice length in big endian as a uint32.
	// - Remaining bytes: successive groups of 64 bytes containing the
	// serialised curve points.

	binary.BigEndian.PutUint32(dst[:4], uint32(len(c.points)))
	for i, p := range c.points {
		p.GetBytes(dst[curve.PointSizeBytes*i+4:])
	}
}

// SetBytes sets the caller from the given bytes. The format of these bytes is
// that determined by the GetBytes method.
func (c *Commitment) SetBytes(bs []byte) {
	nPoints := int(binary.BigEndian.Uint32(bs[:4]))
	c.points = c.points[:nPoints]
	for i := 0; i < nPoints; i++ {
		c.points[i].SetBytes(bs[curve.PointSizeBytes*i+4:])
	}
}

// SizeHint implements the surge.SizeHinter interface.
func (c *Commitment) SizeHint() int { return curve.PointSizeBytes*len(c.points) + 4 }

// Marshal implements the surge.Marshaler interface.
func (c *Commitment) Marshal(w io.Writer, m int) (int, error) {
	if m < 4 {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [4]byte

	binary.BigEndian.PutUint32(bs[:], uint32(len(c.points)))
	n, err := w.Write(bs[:])
	m -= n
	if err != nil {
		return m, err
	}

	for i := range c.points {
		if m < c.points[i].SizeHint() {
			return m, surge.ErrMaxBytesExceeded
		}

		m, err = c.points[i].Marshal(w, m)
		if err != nil {
			return m, err
		}
	}
	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (c *Commitment) Unmarshal(r io.Reader, m int) (int, error) {
	if m < 4 {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [4]byte
	n, err := io.ReadFull(r, bs[:])
	m -= n
	if err != nil {
		return m, err
	}

	// Number of curve points.
	l := binary.BigEndian.Uint32(bs[:])
	if m < int(l*curve.PointSizeBytes) {
		return m, surge.ErrMaxBytesExceeded
	}

	c.points = c.points[:0]
	for i := 0; i < int(l); i++ {
		c.points = append(c.points, curve.New())
		m, err = c.points[i].Unmarshal(r, m)
		if err != nil {
			return m, err
		}
	}
	return m, nil
}

// NewCommitmentWithCapacity creates a new Commitment with the given capacity.
// This capacity represents the maximum reconstruction threshold, k, that this
// commitment can be used for.
func NewCommitmentWithCapacity(k int) Commitment {
	points := make([]curve.Point, k)
	for i := range points {
		points[i] = curve.New()
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
	var smaller, larger []curve.Point
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
func (c *Commitment) Scale(other *Commitment, scale *secp256k1.Secp256k1N) {
	var bs [FnSizeBytes]byte
	scale.GetB32(bs[:])
	c.points = c.points[:len(other.points)]
	for i := range c.points {
		c.points[i].Scale(&other.points[i], bs)
	}
}

// Evaluates the sharing polynomial at the given index "in the exponent".
func (c *Commitment) evaluate(eval *curve.Point, index *secp256k1.Secp256k1N) {
	var bs [FnSizeBytes]byte
	index.GetB32(bs[:])
	eval.Set(&c.points[len(c.points)-1])
	for i := len(c.points) - 2; i >= 0; i-- {
		eval.Scale(eval, bs)
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
	h curve.Point

	// Cached vairables
	eval, gPow, hPow curve.Point
}

// SizeHint implements the surge.SizeHinter interface.
func (checker *VSSChecker) SizeHint() int { return checker.h.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (checker *VSSChecker) Marshal(w io.Writer, m int) (int, error) {
	var err error = nil
	m, err = checker.h.Marshal(w, m)
	return m, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (checker *VSSChecker) Unmarshal(r io.Reader, m int) (int, error) {
	var err error = nil
	checker.h = curve.New()
	m, err = checker.h.Unmarshal(r, m)
	if err != nil {
		return m, err
	}
	checker.eval = curve.New()
	checker.gPow = curve.New()
	checker.hPow = curve.New()
	return m, nil
}

// NewVSSChecker constructs a new VSS checking instance for the given Pedersen
// commitment scheme parameter h. The other generator g is always chosen to be
// the canonical base point for the secp256k1 curve.
func NewVSSChecker(h curve.Point) VSSChecker {
	eval, gPow, hPow := curve.New(), curve.New(), curve.New()
	return VSSChecker{h, eval, gPow, hPow}
}

// IsValid returns true when the given verifiable share is valid with regard to
// the given commitment, and false otherwise.
func (checker *VSSChecker) IsValid(c *Commitment, vshare *VerifiableShare) bool {
	var bs [FnSizeBytes]byte
	vshare.share.value.GetB32(bs[:])
	checker.gPow.BaseExp(bs)
	vshare.r.GetB32(bs[:])
	checker.hPow.Scale(&checker.h, bs)
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
	h      curve.Point

	// Cached variables
	shares Shares
	hPow   curve.Point
}

// SizeHint implements the surge.SizeHinter interface.
func (s *VSSharer) SizeHint() int { return s.sharer.SizeHint() + s.h.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (s *VSSharer) Marshal(w io.Writer, m int) (int, error) {
	var err error = nil

	m, err = s.sharer.Marshal(w, m)
	if err != nil {
		return m, err
	}

	m, err = s.h.Marshal(w, m)
	if err != nil {
		return m, err
	}

	return m, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (s *VSSharer) Unmarshal(r io.Reader, m int) (int, error) {
	var err error = nil

	m, err = s.sharer.Unmarshal(r, m)
	if err != nil {
		return m, err
	}

	s.h = curve.New()
	m, err = s.h.Unmarshal(r, m)
	if err != nil {
		return m, err
	}

	s.shares = make(Shares, len(s.sharer.indices))
	s.hPow = curve.New()
	return m, nil
}

// NewVSSharer constructs a new VSSharer from the given set of indices.
func NewVSSharer(indices []secp256k1.Secp256k1N, h curve.Point) VSSharer {
	sharer := NewSharer(indices)
	shares := make(Shares, len(indices))
	hPow := curve.New()
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
func (s *VSSharer) Share(vshares *VerifiableShares, c *Commitment, secret secp256k1.Secp256k1N, k int) error {
	err := s.sharer.Share(&s.shares, secret, k)
	if err != nil {
		return err
	}

	// At this point, the sharer should still have the randomly picked
	// coefficients in its cache, which we need to use for the commitment.
	var bs [FnSizeBytes]byte
	c.points = c.points[:k]
	for i, coeff := range s.sharer.coeffs {
		coeff.GetB32(bs[:])
		c.points[i].BaseExp(bs)
	}

	s.sharer.setRandomCoeffs(secp256k1.RandomSecp256k1N(), k)
	for i, ind := range s.sharer.indices {
		(*vshares)[i].share = s.shares[i]
		polyEval(&(*vshares)[i].r, &ind, s.sharer.coeffs)
	}

	// Finish the computation of the commitments
	for i, coeff := range s.sharer.coeffs {
		coeff.GetB32(bs[:])
		s.hPow.Scale(&s.h, bs)
		c.points[i].Add(&c.points[i], &s.hPow)
	}

	return nil
}
