package poly

import (
	"math/rand"
	"reflect"

	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"
)

// Interpolator can perform polynomial interpolation. That is, the act of
// taking a set of points on a polynomial and finding a polynomial that passes
// through all of those points. This is encapsulated in an object because when
// interpolating multiple sets of points, all of which have the same set of
// corresponding x coordinates, each interpolation can use the same setup,
// improving efficiency.
type Interpolator struct {
	basis []Poly
}

// NewInterpolator constructs a new polynomial interpolator for the given set
// of indices. The indices represent the x coordinates of the points that will
// be interpolated. That is, if the set of indices is `{x0, x1, ..., xn}`, then
// the constructed interpolator will be able to interpolate any set of points
// of the form `{(x0, y0), (x1, y1), ..., (xn, yn)}` for any `y0, y1, ..., yn`.
func NewInterpolator(indices []secp256k1.Fn) Interpolator {
	// Interpolation will use Lagrange polynomial interpolation

	// One basis polynomial for each index
	basis := make([]Poly, len(indices))
	for i := range basis {
		// Each basis polynomial has degree equal to the number of indices
		// minus one
		basis[i] = NewWithCapacity(len(indices))
	}

	numerator := NewWithCapacity(2)
	var denominator secp256k1.Fn

	// Compute basis polynomials
	numerator = numerator[:2]
	for i := range basis {
		basis[i][0].SetU16(1)

		for j := range indices {
			if i == j {
				continue
			}

			// Numerator x - xj
			numerator[0].Negate(&indices[j])
			numerator[1].SetU16(1)

			// Denominator xi - xj
			denominator.Negate(&indices[j])
			denominator.Add(&denominator, &indices[i])

			// (x - xj)/(xi - xj)
			denominator.Inverse(&denominator)
			numerator.ScalarMul(numerator, denominator)

			basis[i].Mul(basis[i], numerator)
		}
	}

	return Interpolator{basis}
}

// Interpolate takes a set of values representing polynomial evaluations, and
// computes a polynomial that interpolates these values, storing the result in
// `poly`. It is assumed that the values are in corresponding order to the
// indices that were used to constructd the interpolator. That is, if the
// interpolator was constructed using the set of indices `{x0, x1, ..., xn}`,
// then calling this function with the values `{y0, y1, ..., yn}` will find the
// interpolating polynomial for the set of points `{(x0, y0), (x1, y1), ...,
// (xn, yn)}`.
func (interp *Interpolator) Interpolate(values []secp256k1.Fn, poly *Poly) {
	// Polynomial is a linear combination of the Lagrange basis

	// In the first iteration we set the polynomial in case it was non-zero
	poly.Set(interp.basis[0])
	poly.ScalarMul(*poly, values[0])

	for i := 1; i < len(interp.basis); i++ {
		poly.AddScaled(*poly, interp.basis[i], values[i])
	}
}

// Generate implements the quick.Generator interface.
func (interp Interpolator) Generate(_ *rand.Rand, size int) reflect.Value {
	n := rand.Intn(size + 1)
	m := size / (n + 1)
	basis := make([]Poly, n)
	for i := range basis {
		basis[i] = make(Poly, m)
		for j := range basis[i] {
			basis[i][j] = secp256k1.RandomFn()
		}
	}
	return reflect.ValueOf(Interpolator{basis: basis})
}

// SizeHint implements the surge.SizeHinter interface.
func (interp Interpolator) SizeHint() int { return surge.SizeHint(interp.basis) }

// Marshal implements the surge.Marshaler interface.
func (interp Interpolator) Marshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Marshal(interp.basis, buf, rem)
}

// Unmarshal implements the surge.Unmarshaler interface.
func (interp *Interpolator) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	return surge.Unmarshal(&interp.basis, buf, rem)
}
