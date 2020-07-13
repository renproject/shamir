package poly

import (
	"fmt"

	"github.com/renproject/secp256k1"
)

// Poly represents a polynomial in the field defined by the elliptic curve
// secp256k1. That is, the field of integers modulo n where n is the order of
// the secp256k1 group.
//
// A Poly can be indexed into, where index `i` will be the `i`th coefficient.
// For example, the constant term is index 0.
//
// Since this type just aliases a slice, all of the considerations of using a
// slice apply. For example, attempting to access coefficients outside of the
// length bound will panic, as will using a polynomial in a context where its
// capacity is too small (e.g. copying a polynomial that is too large for the
// destination's capacity). The fact that this type is an alias also means that
// it is possible to directly modify properties of the slice and the underlying
// memory. To ensure the correct functioning of this type, these manual
// modificaitons should be avoided, and rather the provided methods used.
type Poly []secp256k1.Fn

// NewPolyFromSlice constructs a polynomial from a given slice. There will be
// no further initialisation; the coefficients of the polynomial will be
// determined by whatever values are currently in the slice, and the degree of
// the polynomial will be determined by the length of the slice. Specifically,
// the degree will be one less than the length of the slice. The capacity of
// the polynomial will be the capacity of the slice.
//
// NOTE: The underlying memory is not copied over from the input slice. This
// means that if the original slice is used to modify the underlying memory in
// any way, these modifications will be reflected in the polynomial too. It is
// therefore advised that the original slice should not be modified in any way
// after calling this function.
func NewPolyFromSlice(coeffs []secp256k1.Fn) Poly {
	return Poly(coeffs)
}

// NewPolyWithCapacity constructs a new polynomial with the given capacity. The
// polynomial will also be initialised to the zero polynomial.
//
// NOTE: This function will panic if the argument is less than 1.
func NewPolyWithCapacity(c int) Poly {
	coeffs := make([]secp256k1.Fn, c)
	poly := Poly(coeffs)

	// Make it the zero polynomial
	poly.Zero()

	return poly
}

// String implements the Stringer interface
func (p Poly) String() string {
	var coeff secp256k1.Fn

	coeff = *p.Coefficient(0)
	str := fmt.Sprintf("%v", coeff.Int())

	for i := 1; i <= p.Degree(); i++ {
		coeff = *p.Coefficient(i)

		if i == 1 {
			str += fmt.Sprintf(" + %v x", coeff.Int())
		} else {
			str += fmt.Sprintf(" + %v x^%v", coeff.Int(), i)
		}
	}

	return str
}

// Degree returns the degree of the polynomial. This is the exponent of the
// highest term with non-zero coefficient. For example, 3x^2 + 2x + 1 has
// degree 2.
func (p Poly) Degree() int {
	return len(p) - 1
}

// Coefficient returns a pointer to the `i`th coefficient of the polynomial.
//
// NOTE: If `i` is geater than the degree of the polynomial, this function will
// panic.
func (p Poly) Coefficient(i int) *secp256k1.Fn {
	return &p[i]
}

// Set copies a given polynomial into the destination polynomial. Since the
// memory is copied, the argument will remain unchanged.
func (p *Poly) Set(a Poly) {
	// copy will only copy min(len(dst), len(src)) elements, so we need to make
	// sure that the destination slice has the right length
	p.setLenByDegree(a.Degree())

	copy(*p, a)
}

// IsZero returns true if the polynomial is the zero polynomial, and false
// otherwise. The zero polynomial is defined to have degree 0 and a constant
// term that is equal to 0 (the additive identity in the field).
func (p *Poly) IsZero() bool {
	if p.Degree() != 0 {
		return false
	}

	return p.Coefficient(0).IsZero()
}

// Eq returns true if the two polynomials are equal and false if they are not.
// Equality of polynomials is defined as all coefficients being equal.
func (p *Poly) Eq(other Poly) bool {
	// Short circuit if the polynomials have different degrees
	if p.Degree() != other.Degree() {
		return false
	}

	// Otherwise check each coefficient
	var temp1, temp2 secp256k1.Fn
	for i := range *p {
		temp1 = *p.Coefficient(i)
		temp2 = *other.Coefficient(i)

		if !temp1.Eq(&temp2) {
			return false
		}
	}

	return true
}

// Zero sets the polynomial to the zero polynomial (additive identity). That
// is, the polynomial of degree 0 with constant term coefficient also equal to
// 0.
func (p *Poly) Zero() {
	p.setLenByDegree(0)
	p.Coefficient(0).Clear()
}

// Sets the length of the underlying slice to be such that it can hold a
// polynomial of the given degree.
func (p *Poly) setLenByDegree(degree int) {
	(*p) = (*p)[:degree+1]
}

// Ensures that the x^deg(p) coefficient of the polynomial is non zero by
// possibly reducing its Degree().
func (p *Poly) removeLeadingZeros() {
	for p.Degree() > 0 && p.Coefficient(p.Degree()).IsZero() {
		p.setLenByDegree(p.Degree() - 1)
	}
}

// Evaluate computes the value of the polynomial at the given point.
func (p *Poly) Evaluate(x secp256k1.Fn) secp256k1.Fn {
	var res secp256k1.Fn

	res = *p.Coefficient(p.Degree())

	for i := p.Degree() - 1; i >= 0; i-- {
		res.Mul(&res, &x)
		res.Add(&res, p.Coefficient(i))
	}

	return res
}

// ScalarMul computes the multiplication of the input polynomial by the input
// scale factor from the field that the polynomial is defined over. This
// function is safe for aliasing: the argument may be an alias of the caller.
//
// NOTE: If the destination polynomial doesn't have sufficient capacity to
// store the result, this function will panic. To ensure that the destination
// has enough capacity, it is enough to ensure that the capacity is at least as
// big as `deg(a) + 1`.
func (p *Poly) ScalarMul(a Poly, s secp256k1.Fn) {
	// Short circuit conditions
	if s.IsZero() {
		p.Zero()
		return
	}
	if s.IsOne() {
		p.Set(a)
		return
	}

	p.setLenByDegree(a.Degree())
	for i := range *p {
		p.Coefficient(i).Mul(a.Coefficient(i), &s)
	}
}

// Add computes the addition of the two input polynomials and stores the result
// in the caller. This function is safe for aliasing: either (and possible
// both) of the input polynomials may be an alias of the caller.
//
// NOTE: If the destination polynomial doesn't have sufficient capacity to
// store the result, this function will panic. To ensure that the destination
// has enough capacity, it is enough to ensure that the capacity is at least as
// big as `max(deg(a), deg(b)) + 1`. It is possible that the result will have
// degree smaller than this, but this will only happen in the case that some of
// the leading terms cancel.
func (p *Poly) Add(a, b Poly) {
	if a.Degree() > b.Degree() {
		p.setLenByDegree(a.Degree())
		for i := range b {
			p.Coefficient(i).Add(a.Coefficient(i), b.Coefficient(i))
		}
		copy((*p)[b.Degree()+1:], a[b.Degree()+1:])
	} else {
		p.setLenByDegree(b.Degree())
		for i := range a {
			p.Coefficient(i).Add(a.Coefficient(i), b.Coefficient(i))
		}
		copy((*p)[a.Degree()+1:], b[a.Degree()+1:])
	}

	if a.Degree() == b.Degree() {
		// Account for the fact that the leading coefficients of a and b may
		// have cancelled eachother
		p.removeLeadingZeros()
	}
}

// AddScaled computes the addition of the first polynomial and a scaled version
// of the second polynomial and stores the result in the caller. This is
// equivalent to doing the scaling and then the addition separately, but allows
// for better memory efficiency. This function is safe for aliasing: either
// (and possible both) of the input polynomials may be an alias of the caller.
//
// NOTE: If the destination polynomial doesn't have sufficient capacity to
// store the result, this function will panic. To ensure that the destination
// has enough capacity, it is enough to ensure that the capacity is at least as
// big as `max(deg(a), deg(b)) + 1`. It is possible that the result will have
// degree smaller than this, but this will only happen in the case that some of
// the leading terms cancel.
func (p *Poly) AddScaled(a, b Poly, s secp256k1.Fn) {
	var scaled secp256k1.Fn

	if a.Degree() > b.Degree() {
		p.setLenByDegree(a.Degree())
		for i := range b {
			scaled.Mul(&s, b.Coefficient(i))
			p.Coefficient(i).Add(a.Coefficient(i), &scaled)
		}
		copy((*p)[b.Degree()+1:], a[b.Degree()+1:])
	} else {
		p.setLenByDegree(b.Degree())
		for i := range a {
			scaled.Mul(&s, b.Coefficient(i))
			p.Coefficient(i).Add(a.Coefficient(i), &scaled)
		}
		for i := a.Degree() + 1; i <= b.Degree(); i++ {
			p.Coefficient(i).Mul(b.Coefficient(i), &s)
		}
	}

	if a.Degree() == b.Degree() {
		// Account for the fact that the leading coefficients of a and b may
		// have cancelled eachother
		p.removeLeadingZeros()
	}
}

// Sub subtracts the second polynomial from the first polynomial and stores the
// result in the destination polynomial. This function is safe for aliasing:
// either (and possible both) of the input polynomials may be an alias of the
// caller.
//
// NOTE: If the destination polynomial doesn't have sufficient capacity to
// store the result, this function will panic. To ensure that the destination
// has enough capacity, it is enough to ensure that the capacity is at least as
// big as `max(deg(a), deg(b)) + 1`. It is possible that the result will have
// degree smaller than this, but this will only happen in the case that some of
// the leading terms cancel.
func (p *Poly) Sub(a, b Poly) {
	// Temporary value to store the negative of the coefficients from b
	var neg secp256k1.Fn

	if a.Degree() > b.Degree() {
		p.setLenByDegree(a.Degree())
		for i := range b {
			neg.Negate(b.Coefficient(i))
			p.Coefficient(i).Add(a.Coefficient(i), &neg)
		}

		// The remaining coefficients are just those of a
		copy((*p)[b.Degree()+1:], a[b.Degree()+1:])
	} else {
		p.setLenByDegree(b.Degree())
		for i := range a {
			neg.Negate(b.Coefficient(i))
			p.Coefficient(i).Add(a.Coefficient(i), &neg)
		}

		// The remaining terms are negatives of the coefficients of b
		for i := a.Degree() + 1; i <= b.Degree(); i++ {
			p.Coefficient(i).Negate(b.Coefficient(i))
		}
	}

	if a.Degree() == b.Degree() {
		// Account for the fact that the leading coefficients of a and b may
		// have cancelled eachother
		p.removeLeadingZeros()
	}
}

// Neg computes the negation of the polynomial and stores it in the destination
// polynomial. This function is safe for aliasing: the argument may be an alias
// of the caller.
//
// NOTE: If the destination polynomial doesn't have sufficient capacity to
// store the result, this function will panic. To ensure that the destination
// has enough capacity, it is enough to ensure that the capacity is at least as
// big as `deg(a) + 1`.
func (p *Poly) Neg(a Poly) {
	// Zero out any leading terms of higher Degree() than a
	p.setLenByDegree(a.Degree())

	for i := range *p {
		p.Coefficient(i).Negate(a.Coefficient(i))
	}
}

// Mul copmutes the product of the two polynomials and stores the result in the
// destination polynomial. This function is not safe when the two input
// polynomials are aliases of eachother as well as the destination; in this
// case the multiplication will give an incorrect result. The exception to this
// is when the polynomial has degree 0. Otherwise, either input polynomial may
// individually be an alias of the destination polynomial or be aliases of
// eachother (but not the destination) and still be safe.
//
// NOTE: If the destination polynomial doesn't have sufficient capacity to
// store the result, this function will panic. To ensure that the destination
// has enough capacity, it is enough to ensure that the capacity is at least as
// big as `deg(a) + deg(b) + 1`.
func (p *Poly) Mul(a, b Poly) {
	// Short circuit if either polynomial is zero
	if a.IsZero() || b.IsZero() {
		p.Zero()
		return
	}

	// In order to allow for the case that p == a or p == b, we need to make
	// sure that we do not clobber coefficients before we have finished using
	// them. To do this, we populate the higher Degree() coefficients first.
	// However, we need to consider that, for instance, the coefficient for the
	// x^1 term is equal to a0b1 + a1b0, which clearly uses the x^1 coefficient
	// of both a and b. We therefore need to check which of a and b are aliased
	// by p, and make sure to use the higher Degree() coefficient of the
	// aliased polynomial first in our sum, before it gets clobbered.
	//
	// We need to check that the slices point to the same memory. Go doesn't
	// allow comparison of slices other than to the nil value, so we use the
	// following workaround wherein we compare the addresses of the first
	// elements of the slices instead.
	aliasedA := &(*p)[0] == &a[0]

	p.setLenByDegree(a.Degree() + b.Degree())
	var aStart, bStart, numTerms int
	var ab secp256k1.Fn

	// If p aliases a, then we need to count down in the coefficients of a to
	// avoid clobbering values that we will need to use
	if aliasedA {
		for i := a.Degree() + b.Degree(); i >= 0; i-- {
			aStart = min(a.Degree(), i)
			bStart = max(0, i-a.Degree())
			numTerms = min(aStart, b.Degree()-bStart)

			// Account for the fact that initially the memory might not be
			// zeroed
			ab.Mul(a.Coefficient(aStart), b.Coefficient(bStart))
			*p.Coefficient(i) = ab

			for j := 1; j <= numTerms; j++ {
				// Count down in a and up in b
				ab.Mul(a.Coefficient(aStart-j), b.Coefficient(bStart+j))
				p.Coefficient(i).Add(p.Coefficient(i), &ab)
			}
		}
	} else {
		// It is possible that p does not aliase either a or b here, but in
		// this case either of the branches would work so we don't need to
		// consider this case separately

		for i := a.Degree() + b.Degree(); i >= 0; i-- {
			aStart = max(0, i-b.Degree())
			bStart = min(b.Degree(), i)
			numTerms = min(a.Degree()-aStart, bStart)

			// Account for the fact that initially the memory might not be
			// zeroed
			ab.Mul(a.Coefficient(aStart), b.Coefficient(bStart))
			*p.Coefficient(i) = ab

			for j := 1; j <= numTerms; j++ {
				// Count up in a and down in b
				ab.Mul(a.Coefficient(aStart+j), b.Coefficient(bStart-j))
				p.Coefficient(i).Add(p.Coefficient(i), &ab)
			}
		}
	}
}

// Divide computes the division of `a` by `b`, storing the quotient in `q` and
// the remainder in `r`. That is, after calling this function, the polynomials
// should satisfy `a = bq + r`. Note that if either `q` or `r` are aliased by
// either `a` or `b`, the result will be incorrect. This is also true if `q` is
// an alias of `r`. The inputs `a` and `b` are not modified and can therefore
// also be aliases of eachother.
//
// NOTE: If the destination polynomials (i.e. `q` and `r`) don't have
// sufficient capacity to store the result, this function will panic. To ensure
// that these polynomials have enough capacity, it is sufficient to ensure that
// `q` has a capacity of at least `deg(a) - deg(b) + 1`, and that `r` has a
// capacity of at least `deg(a) + 1`.
func Divide(a, b Poly, q, r *Poly) {
	// Short circuit when the division is trivial
	if b.Degree() > a.Degree() {
		q.Zero()
		r.Set(a)
		return
	}

	var c, s, bs, cInv secp256k1.Fn
	var d, diff int

	r.Set(a)
	d = b.Degree()
	c = *b.Coefficient(b.Degree())
	q.setLenByDegree(r.Degree() - d)
	cInv.Inverse(&c)

	for r.Degree() >= d {
		s.Mul(&cInv, r.Coefficient(r.Degree()))

		// q = q + sx^(deg(r) - d)
		diff = r.Degree() - d
		*q.Coefficient(diff) = s

		// r = r - b sx^(deg(r) - d)
		for i := range b {
			bs.Mul(&s, b.Coefficient(i))
			bs.Negate(&bs)
			r.Coefficient(diff+i).Add(r.Coefficient(diff+i), &bs)
		}
		r.setLenByDegree(r.Degree() - 1)
		r.removeLeadingZeros()
	}

	// In the case that r = 0, we need to fix the data representation
	if len(*r) == 0 {
		r.Zero()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
