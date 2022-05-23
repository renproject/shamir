package ed25519

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"unsafe"

	"filippo.io/edwards25519"
	"github.com/renproject/surge"
)

// extended Scalar
type Scalar struct {
	inner edwards25519.Scalar
}

const ScalarSizeMarshalled = 32

// ScalarSize is the number of bytes needed to represent a curve point in memory.
const ScalarSize int = int(unsafe.Sizeof(Scalar{}))

// SizeHint implements the surge.SizeHinter interface.
func (s Scalar) SizeHint() int { return ScalarSizeMarshalled }

// Marshal implements the surge.Marshaler interface.
func (s Scalar) Marshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < ScalarSizeMarshalled || rem < 32 {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}

	s.PutB32(buf[:ScalarSizeMarshalled])

	return buf[ScalarSizeMarshalled:], rem - ScalarSizeMarshalled, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (s *Scalar) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < ScalarSizeMarshalled || rem < ScalarSize {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}

	s.SetB32(buf[:ScalarSizeMarshalled])

	return buf[ScalarSizeMarshalled:], rem - ScalarSize, nil
}

// PutB32 stores the bytes of the field element into destination in little endian
// form.
//
// Panics: If the byte slice has length less than 32, this function will panic.
func (s Scalar) PutB32(dst []byte) {
	if len(dst) < 32 {
		panic(fmt.Sprintf("invalid slice length: length needs to be at least 32, got %v", len(dst)))
	}
	// currently we store bytes in little endian format
	copy(dst, s.inner.Bytes())
}

// SetB32 sets the field element to be equal to the given byte slice,
// interepreted as big endian. The field element will be reduced modulo N. This
// function will return true if the bytes represented a number greater than or
// equal to N, and false otherwise.
//
// Panics: If the byte slice has length less than 32, this function will panic.

func (s *Scalar) SetB32(bs []byte) error {
	if len(bs) < 32 {
		panic(fmt.Sprintf("invalid slice length: length needs to be at least 32, got %v", len(bs)))
	}
	_, err := s.inner.SetCanonicalBytes(bs)
	if err != nil {
		return fmt.Errorf("unable to set canonical bytes for scalar: %v", err)
	}
	return nil
}

// Get random scalar
func RandomScalar() Scalar {
	var b [64]byte
	var s Scalar
	_, err := rand.Read(b[:])
	if err != nil {
		panic(fmt.Sprintf("error generating random bytes: %v", err))
	}

	s.inner.SetUniformBytes(b[:])
	return s
}

// Check if two scalars are equal
func (s *Scalar) Eq(other *Scalar) bool {
	return 1 == s.inner.Equal(&other.inner)
}

// sets s = -other mod l
func (s *Scalar) Negate(other *Scalar) {
	s.inner.Negate(&other.inner)
}

// sets s = other^-1 mod l or sets to 0
func (s *Scalar) Inverse(other *Scalar) {
	s.inner.Invert(&other.inner)
}

// Adds two scalars
func (s *Scalar) Add(a, b *Scalar) {
	s.inner.Add(&a.inner, &b.inner)
}

// Multiplies two scalars
func (s *Scalar) Mul(a, b *Scalar) {
	s.inner.Multiply(&a.inner, &b.inner)
}

// Clear sets the underlying data of the structure to zero. This will leave it
// in a state which is a representation of the zero element.
func (s *Scalar) Clear() {
	s.inner = edwards25519.Scalar{}
}

// Checks if the scalar is zero
func (s *Scalar) IsZero() bool {
	return s.inner == edwards25519.Scalar{}
}

// sets a uint32 value to a scalar
func (s *Scalar) SetU32(i uint32) {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b, i)
	_, err := s.inner.SetCanonicalBytes(b)
	if err != nil {
		panic(fmt.Sprintf("cannot set uint32 value to ed25519 scalar: %v", err))
	}
}

// sets a uint64 value to a scalar
func (s *Scalar) SetU64(i uint64) {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint64(b, i)
	_, err := s.inner.SetCanonicalBytes(b)
	if err != nil {
		panic(fmt.Sprintf("cannot set uint64 value to ed25519 scalar: %v", err))
	}
}
