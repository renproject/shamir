package curve

import (
	"errors"
	"fmt"
	"io"
	"math/big"

	ec "github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/renproject/secp256k1-go"
	"github.com/renproject/surge"
)

// PointSizeBytes is the size of a curve point in bytes.
const PointSizeBytes = 64

// Point represents a point on the secp256k1 elliptice curve.
type Point struct {
	x, y       *big.Int
	isInfinity bool
}

// String implements the Stringer interface.
func (p Point) String() string {
	return fmt.Sprintf("(%v, %v, %v)", p.x, p.y, p.isInfinity)
}

// GetBytes serialises the curve point into bytes and writes these bytes into
// the given destination slice. A curve point serialises to 64 bytes.
//
// Panics: If the destination slice has length less than 64, this function may
// panic.
func (p *Point) GetBytes(dst []byte) {
	// Byte format:
	//
	// - First 32 bytes: big endian bytes of the x coordinate, left padded with
	// zeros.
	// - Second 32 bytes: big endian bytes of the y coordinate, left padded
	// with zeros.

	xBytes := p.x.Bytes()
	yBytes := p.y.Bytes()
	copy(dst[32-len(xBytes):], xBytes)
	copy(dst[64-len(yBytes):], yBytes)

	// Make sure the remaining bytes of the slice are zeroed.
	for i := range dst[:32-len(xBytes)] {
		dst[i] = 0
	}
	offset := 32
	for i := range dst[offset : 64-len(yBytes)] {
		dst[offset+i] = 0
	}
}

// SetBytes sets the caller from the given bytes. The format of these bytes is
// that determined by the GetBytes method.
func (p *Point) SetBytes(bs []byte) {
	i := 0
	for _, b := range bs[:32] {
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
	p.y.SetBytes(bs[i:64])
}

// SizeHint implements the surge.SizeHinter interface.
func (p *Point) SizeHint() int { return PointSizeBytes }

// Marshal implements the surge.Marshaler interface.
func (p *Point) Marshal(w io.Writer, m int) (int, error) {
	if m < PointSizeBytes {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [PointSizeBytes]byte
	p.GetBytes(bs[:])
	n, err := w.Write(bs[:])
	return m - n, err
}

// Unmarshal implements the surge.Unmarshaler interface.
//
// NOTE: If the data does not represent a point on the elliptic curve, an error
// will be returned.
func (p *Point) Unmarshal(r io.Reader, m int) (int, error) {
	if m < PointSizeBytes {
		return m, surge.ErrMaxBytesExceeded
	}

	// This will only ever read 64 bytes from the reader.
	var bs [PointSizeBytes]byte
	n, err := io.ReadFull(r, bs[:])
	if err != nil {
		return m - n, err
	}

	// Set the point and make sure it is valid.
	p.SetBytes(bs[:])
	if !p.IsOnCurve() {
		return m - n, errors.New("point is not on the elliptic curve")
	}
	return m - n, nil
}

// New constructs a new curve point.
func New() Point {
	x, y := big.NewInt(0), big.NewInt(0)
	return Point{x, y, false}
}

// Infinity constructs a point at infinity
func Infinity() Point {
	x, y := big.NewInt(0), big.NewInt(0)
	return Point{x, y, true}
}

// NewFromCoords constructs a new curve point from the given x and y
// coordinates.
//
// NOTE: This function does not check that the point is actually on the curve.
func NewFromCoords(x, y *big.Int) Point {
	return Point{x, y, false}
}

// IsOnCurve returns true if the x and y coordinates of the caller lie on the
// secp256k1 elliptic curve, and false otherwise.
// TODO: should we simply return true if the point is point at infinity?
func (p *Point) IsOnCurve() bool {
	return ec.S256().IsOnCurve(p.x, p.y)
}

// Set sets the calling curve point to be equal to the given curve point.
func (p *Point) Set(other *Point) {
	p.x.Set(other.x)
	p.y.Set(other.y)
	p.isInfinity = other.isInfinity
}

// Eq returns true if the two curve points are equal, and false otherwise.
func (p *Point) Eq(other *Point) bool {
	if p.isInfinity && other.isInfinity {
		return true
	}

	return p.x.Cmp(other.x) == 0 && p.y.Cmp(other.y) == 0
}

// BaseExp computes the scalar multiplication of the canonical generator of the
// curve by the scalar represented by the given bytes in big endian format, and
// stores the result in the caller.
func (p *Point) BaseExp(bs [32]byte) {
	// FIXME: Handle the case where the exponent is zero.
	p.x, p.y = ec.S256().ScalarBaseMult(bs[:])
	p.isInfinity = false
}

// Add computes the curve addition of the two given curve points and stores the
// result in the caller.
func (p *Point) Add(a, b *Point) {
	if a.isInfinity && !b.isInfinity {
		p.x = b.x
		p.y = b.y
		p.isInfinity = false
		return
	}

	if !a.isInfinity && b.isInfinity {
		p.x = a.x
		p.y = a.y
		p.isInfinity = false
		return
	}

	if a.isInfinity && b.isInfinity {
		inf := Infinity()
		p.x = inf.x
		p.y = inf.y
		p.isInfinity = inf.isInfinity
		return
	}

	if a.Eq(b) {
		p.x, p.y = ec.S256().Double(a.x, a.y)
		p.isInfinity = false
		return
	}
	p.x, p.y = ec.S256().Add(a.x, a.y, b.x, b.y)
	p.isInfinity = false
}

// Scale computes the scalar multiplication of the given curve point and the
// scalar represented by the given bytes in big endian format, and stores the
// result in the caller.
func (p *Point) Scale(other *Point, bs [32]byte) {
	if other.isInfinity {
		p.x = other.x
		p.y = other.y
		p.isInfinity = other.isInfinity
	}

	p.x, p.y = ec.S256().ScalarMult(other.x, other.y, bs[:])
	p.isInfinity = false
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
