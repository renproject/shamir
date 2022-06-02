package ed25519

import (
	"fmt"
	"unsafe"

	"filippo.io/edwards25519"
	"github.com/renproject/surge"
)

// extended Point
type Point struct {
	inner edwards25519.Point
}

const PointSizeMarshalled = 32

// PointSize is the number of bytes needed to represent a curve point in memory.
const PointSize int = int(unsafe.Sizeof(Point{}))

// SizeHint implements the surge.SizeHinter interface.
func (p Point) SizeHint() int { return PointSizeMarshalled }

// Clear sets the underlying data of the structure to zero. This will leave it
// in a state which is a representation of the zero element.
func (p Point) Clear() {
	p.inner = edwards25519.Point{}
}

// Marshal implements the surge.Marshaler interface.
func (p Point) Marshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < PointSizeMarshalled || rem < 32 {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}
	p.PutB32(buf[:PointSizeMarshalled])

	return buf[PointSizeMarshalled:], rem - PointSizeMarshalled, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (p *Point) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < PointSizeMarshalled || rem < PointSize {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}

	err := p.SetB32(buf[:PointSizeMarshalled])
	if err != nil {
		return buf, rem, fmt.Errorf("can not unmarshal ed25519 point : %v", err)
	}

	return buf[PointSizeMarshalled:], rem - PointSize, nil
}

// PutB32 encodes the bytes of an ed25519 point into destination in little endian
// form. The encoding is 32 bytes long.
//
// Panics: If the byte slice has length less than 32, this function will panic.
func (p Point) PutB32(dst []byte) {
	if len(dst) < 32 {
		panic(fmt.Sprintf("invalid slice length: length needs to be at least 32, got %v", len(dst)))
	}
	// currently we store bytes in little endian format
	copy(dst, p.inner.Bytes())
}

// SetB32 sets the point to be equal to the given byte slice,
// interepreted as big endian.
// Errors: If the byte slice has length less than 32, this function
// will panic. If the byte slice is not a canonical encoding,
// this function will return an error.
func (p *Point) SetB32(bs []byte) error {
	if len(bs) < 32 {
		panic(fmt.Sprintf("invalid slice length: length needs to be at least 32, got %v", len(bs)))
	}
	_, err := p.inner.SetBytes(bs)
	if err != nil {
		return fmt.Errorf("unable to set canonical bytes for scalar: %v", err)
	}
	return nil
}

// Get random point
func RandomPoint() Point {
	var p Point
	bs := RandomScalar()
	p.inner.ScalarBaseMult(&bs.inner)
	return p
}

// Check if two points are equal
func (p *Point) Eq(other *Point) bool {
	return 1 == p.inner.Equal(&other.inner)
}

// sets p = -other mod l
func (p *Point) Negate(other *Point) {
	p.inner.Negate(&other.inner)
}

// Adds two points
func (p *Point) Add(a, b *Point) {
	p.inner.Add(&a.inner, &b.inner)
}

// sets p = scalar * B, where B is the canonical generator
func (p *Point) BaseExp(scalar *Scalar) {
	if scalar == nil {
		panic("expected first argument to not be nil")
	}
	p.inner.ScalarBaseMult(&scalar.inner)
}

func (p *Point) Scale(a *Point, scale *Scalar) {
	if a == nil {
		panic("expected valid point as argument")
	}
	if scale == nil {
		panic("expected valid scalar as argument")
	}
	p.inner.ScalarMult(&scale.inner, &a.inner)

}
