package curve

import (
	"fmt"
	"math/big"

	ec "github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/renproject/secp256k1-go"
)

// Point represents a point on the secp256k1 elliptice curve.
type Point struct {
	x, y *big.Int
}

// String implements the Stringer interface.
func (p Point) String() string {
	return fmt.Sprintf("(%v, %v)", p.x, p.y)
}

func (p *Point) Bytes() [64]byte {
	var bs [64]byte
	xBytes := p.x.Bytes()
	for i := 32 - len(xBytes); i < 32; i++ {
		bs[i] = xBytes[i]
	}
	yBytes := p.y.Bytes()
	for i := 64 - len(yBytes); i < 64; i++ {
		bs[i] = xBytes[i]
	}

	return bs
}

func FromBytes(bs []byte) Point {
	p := Point{
		x: big.NewInt(0),
		y: big.NewInt(0),
	}

	i := 0
	for _, b := range bs {
		if b != 0 {
			break
		}
		i++
	}
	p.x.SetBytes(bs[i:32])

	i = 32
	for _, b := range bs[32:] {
		if b != 0 {
			break
		}
		i++
	}
	p.x.SetBytes(bs[i:64])

	return p
}

// New constructs a new curve point.
func New() Point {
	x, y := big.NewInt(0), big.NewInt(0)
	return Point{x, y}
}

// NewFromCoords constructs a new curve point from the given x and y
// coordinates.
//
// NOTE: This function does not check that the point is actually on the curve.
func NewFromCoords(x, y *big.Int) Point {
	return Point{x, y}
}

// Set sets the calling curve point to be equal to the given curve point.
func (p *Point) Set(other *Point) {
	p.x.Set(other.x)
	p.y.Set(other.y)
}

// Eq returns true if the two curve points are equal, and false otherwise.
func (p *Point) Eq(other *Point) bool {
	return p.x.Cmp(other.x) == 0 && p.y.Cmp(other.y) == 0
}

// BaseExp computes the scalar multiplication of the canonical generator of the
// curve by the scalar represented by the given bytes in big endian format, and
// stores the result in the caller.
func (p *Point) BaseExp(bs [32]byte) {
	p.x, p.y = ec.S256().ScalarBaseMult(bs[:])
}

// Add computes the curve addition of the two given curve points and stores the
// result in the caller.
func (p *Point) Add(a, b *Point) {
	if a.Eq(b) {
		p.x, p.y = ec.S256().Double(a.x, a.y)
		return
	}
	p.x, p.y = ec.S256().Add(a.x, a.y, b.x, b.y)
}

// Scale computes the scalar multiplication of the given curve point and the
// scalar represented by the given bytes in big endian format, and stores the
// result in the caller.
func (p *Point) Scale(other *Point, bs [32]byte) {
	p.x, p.y = ec.S256().ScalarMult(other.x, other.y, bs[:])
}

// Random returns a random point on the elliptic curve.
func Random() Point {
	var bs [32]byte
	r := secp256k1.RandomSecp256k1N()
	r.GetB32(bs[:])
	h := New()
	h.BaseExp(bs)
	return h
}
