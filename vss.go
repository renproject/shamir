package shamir

import (
	"fmt"
	"math/big"

	ec "github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/renproject/secp256k1-go"
)

// A Commitment is used to verify that a sharing has been performed correctly.
type Commitment struct {
	// Curve points that represent commitments to each of the coefficients.
	// Index i corresponds to coefficient c_i.
	points []curvePoint
}

// NewCommitmentWithCapacity creates a new Commitment with the given capacity.
// This capacity represents the maximum reconstruction threshold, k, that this
// commitment can be used for.
func NewCommitmentWithCapacity(k int) Commitment {
	points := make([]curvePoint, k)
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
	var smaller, larger []curvePoint
	if len(a.points) > len(b.points) {
		smaller, larger = b.points, a.points
	} else {
		smaller, larger = a.points, b.points
	}

	c.points = c.points[:len(larger)]
	for i := range smaller {
		c.points[i].add(&smaller[i], &larger[i])
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

// IsValid returns true if the given share is correct with respect to the
// commitment, and false otherwise,
func (c *Commitment) IsValid(share *Share) bool {
	var bs [32]byte
	value := share.Value()
	value.GetB32(bs[:])
	shareComm := curvePoint{}

	shareComm.baseExp(bs)
	eval := c.evaluate(share.Index())
	return shareComm.eq(&eval)
}

func (c *Commitment) evaluate(index secp256k1.Secp256k1N) curvePoint {
	// Evaluate the polynomial in the exponent
	eval := newCurvePoint()
	eval.set(&c.points[len(c.points)-1])
	for i := len(c.points) - 2; i >= 0; i-- {
		eval.scale(&eval, &index)
		eval.add(&eval, &c.points[i])
	}

	return eval
}

// A VSSharer is capable of creating a verifiable sharing of a secret, which is
// just a normal Shamir sharing but with the addition of a commitment which is
// a collection of commitments to each of the coefficients of the sharing.
type VSSharer struct {
	sharer Sharer
}

// NewVSSharer constructs a new VSSharer from the given set of indices.
func NewVSSharer(indices []secp256k1.Secp256k1N) VSSharer {
	sharer := NewSharer(indices)
	return VSSharer{sharer}
}

// Share creates verifiable Shamir shares for the given secret at the given
// threshold, and stores the shares and the commitment in the given
// destinations. In the returned Shares, there will be one share for each index
// in the indices that were used to construct the Sharer.
//
// Panics: This function will panic if the destination shares slice has a
// capacity less than n (the number of indices), or if the destination
// commitment has a capacity less than k.
func (s *VSSharer) Share(shares *Shares, c *Commitment, secret secp256k1.Secp256k1N, k int) error {
	err := s.sharer.Share(shares, secret, k)
	if err != nil {
		return err
	}

	// At this point, the sharer should still have the randomly picked
	// coefficients in its cache, which we need to use for the commitment.
	var bs [32]byte
	c.points = c.points[:k]
	for i, coeff := range s.sharer.coeffs {
		coeff.GetB32(bs[:])
		c.points[i].baseExp(bs)
	}

	return nil
}

type curvePoint struct {
	x, y *big.Int
}

func (p *curvePoint) set(other *curvePoint) {
	p.x.Set(other.x)
	p.y.Set(other.y)
}

func (p curvePoint) String() string {
	return fmt.Sprintf("(%v, %v)", p.x, p.y)
}

func newCurvePoint() curvePoint {
	x, y := big.NewInt(0), big.NewInt(0)
	return curvePoint{x, y}
}

func (p *curvePoint) eq(other *curvePoint) bool {
	return p.x.Cmp(other.x) == 0 && p.y.Cmp(other.y) == 0
}

func (p *curvePoint) baseExp(bs [32]byte) {
	p.x, p.y = ec.S256().ScalarBaseMult(bs[:])
}

func (p *curvePoint) add(a, b *curvePoint) {
	p.x, p.y = ec.S256().Add(a.x, a.y, b.x, b.y)
}

func (p *curvePoint) scale(other *curvePoint, scale *secp256k1.Secp256k1N) {
	// Short circuit if the index is one
	if scale.IsOne() {
		p.x, p.y = other.x, other.y
	}

	var bs [32]byte
	scale.GetB32(bs[:])
	p.x, p.y = ec.S256().ScalarMult(other.x, other.y, bs[:])
}
