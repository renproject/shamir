package shamir

import (
	"fmt"
	"math/big"

	ec "github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/renproject/secp256k1-go"
)

type Commitment struct {
	// Curve points that represent commitments to each of the coefficients.
	// Index i corresponds to coefficient c_i.
	points []curvePoint
}

func NewCommitmentWithCapacity(c int) Commitment {
	points := make([]curvePoint, c)
	return Commitment{points}
}

func (c *Commitment) Add(a, b *Commitment) {
	if len(a.points) != len(b.points) {
		panic(fmt.Sprintf(
			"cannot add commitments of different lengths: lhs has k = %v, rhs has k = %v",
			len(a.points),
			len(b.points),
		))
	}

	c.points = c.points[:len(a.points)]
	for i := range c.points {
		c.points[i].add(&a.points[i], &b.points[i])
	}
}

func (c *Commitment) Scale(other *Commitment, scale *secp256k1.Secp256k1N) {
	c.points = c.points[:len(other.points)]
	for i := range c.points {
		c.points[i].scale(&other.points[i], scale)
	}
}

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

type VSSharer struct {
	sharer Sharer
}

func NewVSSharer(indices []secp256k1.Secp256k1N) VSSharer {
	sharer := NewSharer(indices)
	return VSSharer{sharer}
}

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
