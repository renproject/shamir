package shamir

import (
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"
)

// VShareSize is the size of a verifiable share in bytes.
const VShareSize = ShareSize + secp256k1.FnSizeMarshalled

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
		*vshares = make(VerifiableShares, 0, l)
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
		shares[i] = vshare.Share
	}

	return shares
}

// A VerifiableShare is a Share but with additional information that allows it
// to be verified as correct for a given commitment to a sharing.
type VerifiableShare struct {
	Share        Share
	Decommitment secp256k1.Fn
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
	return vs.Share.Eq(&other.Share) && vs.Decommitment.Eq(&other.Decommitment)
}

// SizeHint implements the surge.SizeHinter interface.
func (vs VerifiableShare) SizeHint() int { return vs.Share.SizeHint() + vs.Decommitment.SizeHint() }

// Marshal implements the surge.Marshaler interface.
func (vs VerifiableShare) Marshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := vs.Share.Marshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	buf, rem, err = vs.Decommitment.Marshal(buf, rem)
	return buf, rem, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (vs *VerifiableShare) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	buf, rem, err := vs.Share.Unmarshal(buf, rem)
	if err != nil {
		return buf, rem, err
	}

	return vs.Decommitment.Unmarshal(buf, rem)
}

// Add computes the addition of the two input shares and stores the result in
// the caller. This is defined as adding the respective normal (unverifiable)
// shares and adding the respective decommitment values. In general, the
// resulting share will be a share with secret value equal to the sum of the
// two secrets corresponding to the (respective sharings of the) input shares.
func (vs *VerifiableShare) Add(a, b *VerifiableShare) {
	vs.Share.Add(&a.Share, &b.Share)
	vs.Decommitment.Add(&a.Decommitment, &b.Decommitment)
}

// AddConstant computes the addition of the input share and the constant and
// stores the result in the caller. This is defined as adding the constant to
// the normal (unverifiable) share and leaving the decommitment value
// unchanged. In general, the resulting share will be a share with secret value
// equal to the sum of the secret corresponding to the input share and the
// constant.
func (vs *VerifiableShare) AddConstant(other *VerifiableShare, c *secp256k1.Fn) {
	vs.Decommitment = other.Decommitment
	vs.Share.AddConstant(&other.Share, c)
}

// Scale computes the scaling of the input share by given scale factor and
// stores the result in the caller. This is defined as scaling the normal
// (unverifiable) share by the scaling factor and multiplying the decommitment
// value also by the scaling factor. In general, the resulting share will be a
// share with secret value equal to the scale factor multiplied by the secret
// corresponding to the (sharing of the) input share.
func (vs *VerifiableShare) Scale(other *VerifiableShare, scale *secp256k1.Fn) {
	vs.Share.Scale(&other.Share, scale)
	vs.Decommitment.Mul(&other.Decommitment, scale)
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
		*c = make([]secp256k1.Point, 0, l)
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

// Add takes an input commitment and a constant and stores in the caller the
// commitment that represents the addition of this commitment and the constant.
// That is, the new commitment can be used to verify the correctness of the
// sharing defined by adding the constant to the corresponding sharing for the
// input commitment. For example, if `a_i` is a valid share for the commitment
// `a`, and `c` is a constant, then `a_i.AddConstant(c)` will be a valid share
// for the newly constructed commitment.
func (c *Commitment) AddConstant(other Commitment, constant *secp256k1.Fn) {
	c.Set(other)
	point := secp256k1.Point{}
	point.BaseExp(constant)
	(*c)[0].Add(&(*c)[0], &point)
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

// IsValid returns true when the given verifiable share is valid with regard to
// the given commitment, and false otherwise.
func IsValid(h secp256k1.Point, c *Commitment, vshare *VerifiableShare) bool {
	var gPow, hPow, eval secp256k1.Point
	gPow.BaseExp(&vshare.Share.Value)
	hPow.Scale(&h, &vshare.Decommitment)
	gPow.Add(&gPow, &hPow)

	c.evaluate(&eval, &vshare.Share.Index)
	return gPow.Eq(&eval)
}

// VShareSecret creates verifiable Shamir shares for the given secret at the
// given threshold, and stores the shares and the commitment in the given
// destinations. In the returned Shares, there will be one share for each index
// in the indices that were used to construct the Sharer.
//
// Panics: This function will panic if the destination shares slice has a
// capacity less than n (the number of indices), or if the destination
// commitment has a capacity less than k.
func VShareSecret(
	vshares *VerifiableShares,
	c *Commitment,
	indices []secp256k1.Fn,
	h secp256k1.Point,
	secret secp256k1.Fn,
	k int,
) error {
	n := len(indices)
	shares := make(Shares, n)
	coeffs := make([]secp256k1.Fn, k)
	err := ShareAndGetCoeffs(&shares, coeffs, indices, secret, k)
	if err != nil {
		return err
	}

	// At this point, the sharer should still have the randomly picked
	// coefficients in its cache, which we need to use for the commitment.
	*c = (*c)[:k]
	for i, coeff := range coeffs {
		(*c)[i].BaseExp(&coeff)
	}

	setRandomCoeffs(coeffs, secp256k1.RandomFn(), k)
	for i, ind := range indices {
		(*vshares)[i].Share = shares[i]
		polyEval(&(*vshares)[i].Decommitment, &ind, coeffs)
	}

	// Finish the computation of the commitments
	var hPow secp256k1.Point
	for i, coeff := range coeffs {
		hPow.Scale(&h, &coeff)
		(*c)[i].Add(&(*c)[i], &hPow)
	}

	return nil
}
