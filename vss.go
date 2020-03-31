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

func (c *Commitment) Add(other *Commitment) {
	for i, p := range c.points {
		p.add(&p, &other.points[i])
	}
}

func (c *Commitment) Scale(scale secp256k1.Secp256k1N) {
	for _, p := range c.points {
		p.scale(&p, &scale)
	}
}

func (c *Commitment) IsValid(share *Share) bool {
	var bs [32]byte
	index := share.Value()
	index.GetB32(bs[:])
	shareComm := curvePoint{}

	shareComm.baseExp(bs)
	eval := c.evaluate(index)
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

func (c *curvePoint) set(other *curvePoint) {
	c.x.Set(other.x)
	c.y.Set(other.y)
}

func (c curvePoint) String() string {
	return fmt.Sprintf("(%v, %v)", c.x, c.y)
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
