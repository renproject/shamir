package shamir

import (
	"github.com/renproject/secp256k1-go"
)

type VerifiableShare struct {
	share Share
	r     secp256k1.Secp256k1N
}

func NewVerifiableShare(share Share, r secp256k1.Secp256k1N) VerifiableShare {
	return VerifiableShare{share, r}
}

func (vs *VerifiableShare) Add(a, b *VerifiableShare) {
	vs.share.Add(&a.share, &b.share)
	vs.r.Add(&a.r, &b.r)
	vs.r.Normalize()
}

func (vs *VerifiableShare) Scale(other *VerifiableShare, scale *secp256k1.Secp256k1N) {
	vs.share.Scale(&other.share, scale)
	vs.r.Mul(&other.r, scale)
	vs.r.Normalize()
}

type VerifiableShares []VerifiableShare

// A Commitment is used to verify that a sharing has been performed correctly.
type Commitment struct {
	// Curve points that represent commitments to each of the coefficients.
	// Index i corresponds to coefficient c_i.
	points []CurvePoint
}

// NewCommitmentWithCapacity creates a new Commitment with the given capacity.
// This capacity represents the maximum reconstruction threshold, k, that this
// commitment can be used for.
func NewCommitmentWithCapacity(k int) Commitment {
	points := make([]CurvePoint, k)
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
	var smaller, larger []CurvePoint
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
	c.points = c.points[:len(other.points)]
	for i := range c.points {
		c.points[i].scale(&other.points[i], scale)
	}
}

func (c *Commitment) evaluate(eval *CurvePoint, index *secp256k1.Secp256k1N) {
	// Evaluate the polynomial in the exponent
	eval.Set(&c.points[len(c.points)-1])
	for i := len(c.points) - 2; i >= 0; i-- {
		eval.scale(eval, index)
		eval.Add(eval, &c.points[i])
	}
}

type VSSChecker struct {
	h CurvePoint

	// Cached vairables
	eval, gPow, hPow CurvePoint
}

func NewVSSChecker(h CurvePoint) VSSChecker {
	eval, gPow, hPow := NewCurvePoint(), NewCurvePoint(), NewCurvePoint()
	return VSSChecker{h, eval, gPow, hPow}
}

func (checker *VSSChecker) IsValid(c *Commitment, vshare *VerifiableShare) bool {
	var bs [32]byte
	vshare.share.value.GetB32(bs[:])
	checker.gPow.BaseExp(bs)
	vshare.r.GetB32(bs[:])
	checker.hPow.exp(&checker.h, bs)
	checker.gPow.Add(&checker.gPow, &checker.hPow)

	c.evaluate(&checker.eval, &vshare.share.index)
	return checker.gPow.eq(&checker.eval)
}

// A VSSharer is capable of creating a verifiable sharing of a secret, which is
// just a normal Shamir sharing but with the addition of a commitment which is
// a collection of commitments to each of the coefficients of the sharing.
type VSSharer struct {
	sharer Sharer
	h      CurvePoint

	// Cached variables
	shares Shares
	hPow   CurvePoint
}

// NewVSSharer constructs a new VSSharer from the given set of indices.
func NewVSSharer(indices []secp256k1.Secp256k1N, h CurvePoint) VSSharer {
	sharer := NewSharer(indices)
	shares := make(Shares, len(indices))
	hPow := NewCurvePoint()
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
	var bs [32]byte
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
		s.hPow.exp(&s.h, bs)
		c.points[i].Add(&c.points[i], &s.hPow)
	}

	return nil
}
