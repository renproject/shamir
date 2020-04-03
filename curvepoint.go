package shamir

import (
	"fmt"
	"math/big"

	ec "github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/renproject/secp256k1-go"
)

type CurvePoint struct {
	x, y *big.Int
}

func (p *CurvePoint) Set(other *CurvePoint) {
	p.x.Set(other.x)
	p.y.Set(other.y)
}

func (p CurvePoint) String() string {
	return fmt.Sprintf("(%v, %v)", p.x, p.y)
}

func NewCurvePoint() CurvePoint {
	x, y := big.NewInt(0), big.NewInt(0)
	return CurvePoint{x, y}
}

func NewCurvePointFromCoords(x, y *big.Int) CurvePoint {
	return CurvePoint{x, y}
}

func (p *CurvePoint) eq(other *CurvePoint) bool {
	return p.x.Cmp(other.x) == 0 && p.y.Cmp(other.y) == 0
}

func (p *CurvePoint) BaseExp(bs [32]byte) {
	p.x, p.y = ec.S256().ScalarBaseMult(bs[:])
}

func (p *CurvePoint) exp(base *CurvePoint, bs [32]byte) {
	p.x, p.y = ec.S256().ScalarMult(base.x, base.y, bs[:])
}

func (p *CurvePoint) Add(a, b *CurvePoint) {
	if a.eq(b) {
		p.x, p.y = ec.S256().Double(a.x, a.y)
		return
	}
	p.x, p.y = ec.S256().Add(a.x, a.y, b.x, b.y)
}

func (p *CurvePoint) scale(other *CurvePoint, scale *secp256k1.Secp256k1N) {
	// Short circuit if the index is one
	if scale.IsOne() {
		p.x, p.y = other.x, other.y
	}

	var bs [32]byte
	scale.GetB32(bs[:])
	p.x, p.y = ec.S256().ScalarMult(other.x, other.y, bs[:])
}

func RandomCurvePoint() CurvePoint {
	var bs [32]byte
	r := secp256k1.RandomSecp256k1N()
	r.GetB32(bs[:])
	h := NewCurvePoint()
	h.BaseExp(bs)
	return h
}
