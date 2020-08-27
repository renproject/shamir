package poly_test

import (
	"math/rand"
	"testing"

	"github.com/renproject/secp256k1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir/poly"
	"github.com/renproject/shamir/poly/polyutil"
	"github.com/renproject/shamir/shamirutil"
)

var _ = Describe("Polynomials", func() {
	var zero, one secp256k1.Fn

	zero.SetU16(0)
	one.SetU16(1)

	It("should implement the Stringer interface", func() {
		poly := NewWithCapacity(10)
		polyutil.SetRandomPolynomial(&poly, 9)
		_ = poly.String()
	})

	Context("when constructing a polynomial from a slice", func() {
		Specify("the coefficients should correspond to the slice elements", func() {
			trials := 1000
			maxDegree := 20

			var coefficients [21]secp256k1.Fn
			var degree int

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				for i := 0; i <= degree; i++ {
					coefficients[i] = secp256k1.RandomFn()
				}
				poly := NewFromSlice(coefficients[:degree+1])

				for i := range poly {
					Expect(poly.Coefficient(i).Eq(&coefficients[i])).To(BeTrue())
				}
			}
		})
	})

	Context("when constructing a polynomial with a given capacity", func() {
		Specify("it should be zeroed and have the given capacity", func() {
			trials := 1000
			maxDegree := 20

			var c int

			for i := 0; i < trials; i++ {
				c = rand.Intn(maxDegree) + 1
				poly := NewWithCapacity(c)

				// It should be initialised to the zero polynomial
				Expect(poly.IsZero()).To(BeTrue())

				// It should have the right capacity
				Expect(cap(poly)).To(Equal(c))
			}
		})
	})

	Context("when getting the degree of a polynomial", func() {
		It("should be correct", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			poly := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&poly, degree)

				Expect(poly.Degree()).To(Equal(degree))

				// Memory locations beyond the degree should be out of bounds
				Expect(func() { _ = poly.Coefficient(degree + 1) }).To(Panic())
			}
		})
	})

	Context("when setting a polynomial to be equal to another", func() {
		It("should correctly copy into the destination", func() {
			trials := 1000
			maxDegree := 20

			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)

				a.Set(b)

				Expect(a.Eq(b)).To(BeTrue())
			}
		})
	})

	Context("when checking if a polynomial is zero", func() {
		It("should return true when given the zero polynomial", func() {
			poly := NewWithCapacity(1)
			poly = poly[:1]
			poly[0] = zero

			Expect(poly.IsZero()).To(BeTrue())

			// Additional leading zeros should not affect the result.
			for i := 2; i < 10; i++ {
				poly = append(poly, secp256k1.Fn{})
				Expect(poly.IsZero()).To(BeTrue())
				Expect(len(poly)).To(Equal(i))
			}
		})

		It("should return false when given a polynomial with degree 0 but non-zero constant term", func() {
			poly := NewWithCapacity(1)
			poly = poly[:1]
			poly[0] = secp256k1.RandomFn()

			// Ensure that the constant term is non-zero
			for poly.Coefficient(0).IsZero() {
				poly[0] = secp256k1.RandomFn()
			}

			Expect(poly.IsZero()).To(BeFalse())
		})

		It("should return false when given a polynomial with degree greater than zero", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			poly := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree) + 1
				polyutil.SetRandomPolynomial(&poly, degree)

				Expect(poly.IsZero()).To(BeFalse())

				// Should also return false when the constant term is zero
				poly.Coefficient(0).Clear()
				Expect(poly.IsZero()).To(BeFalse())
			}
		})
	})

	Context("when checking if two polynomials are equal", func() {
		It("should return true if the polynomials are equal", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.Set(a)

				Expect(a.Eq(b)).To(BeTrue())

				// The result should remain true when there are additional
				// leading zeros.
				aEx := append(a, secp256k1.Fn{})
				bEx := append(b, secp256k1.Fn{})

				Expect(aEx.Eq(b)).To(BeTrue())
				Expect(len(aEx)).To(Equal(len(a) + 1))

				Expect(a.Eq(bEx)).To(BeTrue())
				Expect(len(bEx)).To(Equal(len(b) + 1))

				Expect(aEx.Eq(bEx)).To(BeTrue())
				Expect(len(aEx)).To(Equal(len(a) + 1))
				Expect(len(bEx)).To(Equal(len(b) + 1))
			}
		})

		It("should return false if the polynomials are not equal", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)

				// Generate a non-zero polynomial
				polyutil.SetRandomPolynomial(&b, degree)
				for b.IsZero() {
					polyutil.SetRandomPolynomial(&b, degree)
				}

				// Gauranteed to be different from a since we are adding a
				// non-zero polynomial to a
				b.Add(a, b)

				Expect(a.Eq(b)).To(BeFalse())
			}
		})

		It("should return false if the polynomials have different degrees", func() {
			trials := 1000
			maxDegree := 20

			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				for degreeB == degreeA {
					degreeB = rand.Intn(maxDegree + 1)
				}
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)

				Expect(a.Eq(b)).To(BeFalse())
			}
		})
	})

	Context("when zeroing a polynomial", func() {
		It("should set the polynomial to the zero polynomial", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			poly := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&poly, degree)

				poly.Zero()

				Expect(poly.IsZero()).To(BeTrue())
			}
		})
	})

	Context("when evaluating a polynomial at a point", func() {
		It("should perform the computation correctly", func() {
			trials := 1000
			maxDegree := 20

			var x, y, eval, term secp256k1.Fn
			var degree int

			poly := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&poly, degree)
				x = secp256k1.RandomFn()

				// Manually evaluate the polynomial
				y = zero
				for j := 0; j <= poly.Degree(); j++ {
					term = *poly.Coefficient(j)
					for k := 0; k < j; k++ {
						term.Mul(&term, &x)
					}

					y.Add(&y, &term)
				}

				eval = poly.Evaluate(x)
				Expect(eval.Eq(&y)).To(BeTrue())
			}
		})
	})

	Context("when scaling a polynomial", func() {
		Specify("the defining relation should hold", func() {
			trials := 1000
			maxDegree := 20

			var scale, term secp256k1.Fn
			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				scale = secp256k1.RandomFn()
				b.ScalarMul(a, scale)

				for j := 0; j <= b.Degree(); j++ {
					term.Mul(&scale, a.Coefficient(j))
					Expect(b.Coefficient(j).Eq(&term)).To(BeTrue())
				}
			}
		})

		It("should yield zero when the scalar is zero", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.ScalarMul(a, zero)

				Expect(b.IsZero()).To(BeTrue())
			}
		})

		It("should be the same when the scalar is one", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.ScalarMul(a, one)

				Expect(b.Eq(a)).To(BeTrue())
			}
		})

		It("should work when the argument is an alias of the caller", func() {
			trials := 1000
			maxDegree := 20

			var scale secp256k1.Fn
			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				scale = secp256k1.RandomFn()
				b.ScalarMul(a, scale)
				a.ScalarMul(a, scale)

				Expect(a.Eq(b)).To(BeTrue())
			}
		})
	})

	Context("when adding polynomials", func() {
		Specify("the defining relationship should hold", func() {
			trials := 1000
			maxDegree := 20

			var coeff secp256k1.Fn
			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				c.Add(a, b)

				// Check the coefficients
				for i := 0; i < shamirutil.Max(degreeA, degreeB); i++ {
					if i > degreeA {
						coeff.Add(&zero, &b[i])
					} else if i > degreeB {
						coeff.Add(&a[i], &zero)
					} else {
						coeff.Add(&a[i], &b[i])
					}
					Expect(c[i].Eq(&coeff)).To(BeTrue())
				}

				// Check the degree
				Expect(addCheckDegree(a, b, c)).To(BeTrue())
			}
		})

		Specify("the degree should be correct if leading coefficients cancel", func() {
			trials := 1000
			maxDegree := 20

			var degree, leadingSame int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				leadingSame = rand.Intn(degree + 1)
				polyutil.SetRandomPolynomial(&a, degree)

				b = b[:len(a)]
				for i := range b {
					if i < degree+1-leadingSame {
						// lower coefficients are random but different to a
						b[i] = secp256k1.RandomFn()
						for b[i].Eq(&a[i]) {
							b[i] = secp256k1.RandomFn()
						}
					} else {
						// upper leadingSame coefficients are the negation of a
						b[i].Negate(&a[i])
					}
				}

				c.Add(a, b)

				// Check the degree
				Expect(addCheckDegree(a, b, c)).To(BeTrue())
			}
		})

		It("should work when the first argument is a alias of the caller", func() {
			trials := 1000
			maxDegree := 20

			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				c.Add(a, b)
				a.Add(a, b)

				Expect(a.Eq(c)).To(BeTrue())
			}
		})

		It("should work when the second argument is an alias of the caller", func() {
			trials := 1000
			maxDegree := 20

			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				c.Add(a, b)
				b.Add(a, b)

				Expect(b.Eq(c)).To(BeTrue())
			}
		})

		It("should work when the first argument is an alias of the second", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)
			d := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.Set(a)
				c.Add(a, b)
				d.Add(a, a)

				Expect(d.Eq(c)).To(BeTrue())
			}
		})

		It("should work when the caller and both arguments are aliases of each other", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.Set(a)
				c.Add(a, b)
				a.Add(a, a)

				Expect(a.Eq(c)).To(BeTrue())
			}
		})
	})

	Context("when adding scaled polynomials", func() {
		It("should behave the same as adding a scaled version of the second argument", func() {
			trials := 1000
			maxDegree := 20

			var scale secp256k1.Fn
			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)
			scaleAdd := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				scale = secp256k1.RandomFn()

				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				c.AddScaled(a, b, scale)

				scaleAdd.ScalarMul(b, scale)
				scaleAdd.Add(a, scaleAdd)

				Expect(c.Eq(scaleAdd)).To(BeTrue())
			}
		})

		It("should work when the first argument is a alias of the caller", func() {
			trials := 1000
			maxDegree := 20

			var scale secp256k1.Fn
			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				scale = secp256k1.RandomFn()

				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				polyutil.SetRandomPolynomial(&b, degree)
				c.AddScaled(a, b, scale)
				a.AddScaled(a, b, scale)

				Expect(a.Eq(c)).To(BeTrue())
			}
		})

		It("should work when the second argument is an alias of the caller", func() {
			trials := 1000
			maxDegree := 20

			var scale secp256k1.Fn
			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				scale = secp256k1.RandomFn()

				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				polyutil.SetRandomPolynomial(&b, degree)
				c.AddScaled(a, b, scale)
				b.AddScaled(a, b, scale)

				Expect(b.Eq(c)).To(BeTrue())
			}
		})

		It("should work when the first argument is an alias of the second", func() {
			trials := 1000
			maxDegree := 20

			var scale secp256k1.Fn
			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)
			d := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				scale = secp256k1.RandomFn()

				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.Set(a)
				c.AddScaled(a, b, scale)
				d.AddScaled(a, a, scale)

				Expect(d.Eq(c)).To(BeTrue())
			}
		})

		It("should work when the caller and both arguments are aliases of each other", func() {
			trials := 1000
			maxDegree := 20

			var scale secp256k1.Fn
			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				scale = secp256k1.RandomFn()

				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.Set(a)
				c.AddScaled(a, b, scale)
				a.AddScaled(a, a, scale)

				Expect(a.Eq(c)).To(BeTrue())
			}
		})
	})

	Context("when subtracting polynomials", func() {
		Specify("the defining relationship should hold", func() {
			trials := 1000
			maxDegree := 20

			var coeff secp256k1.Fn
			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				c.Sub(a, b)

				// Check the coefficients
				for i := 0; i < shamirutil.Max(degreeA, degreeB); i++ {
					if i > degreeA {
						coeff.Negate(&b[i])
					} else if i > degreeB {
						coeff = a[i]
					} else {
						coeff.Negate(&b[i])
						coeff.Add(&a[i], &coeff)
					}
					Expect(c[i].Eq(&coeff)).To(BeTrue())
				}

				// Check the degree
				Expect(subCheckDegree(a, b, c)).To(BeTrue())
			}
		})

		Specify("the degree should be correct if leading coefficients cancel", func() {
			trials := 1000
			maxDegree := 20

			var degree, leadingSame int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				leadingSame = rand.Intn(degree + 1)
				polyutil.SetRandomPolynomial(&a, degree)

				b = b[:len(a)]
				for i := range b {
					if i < degree+1-leadingSame {
						// lower coefficients are random but different to a
						b[i] = secp256k1.RandomFn()
						for b[i].Eq(&a[i]) {
							b[i] = secp256k1.RandomFn()
						}
					} else {
						// upper leadingSame coefficients are the same as a
						b[i] = a[i]
					}
				}

				c.Sub(a, b)

				// Check the degree
				Expect(subCheckDegree(a, b, c)).To(BeTrue())
			}
		})

		It("should work when the first argument is an alias of the caller", func() {
			trials := 1000
			maxDegree := 20

			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				c.Sub(a, b)
				a.Sub(a, b)

				Expect(a.Eq(c)).To(BeTrue())
			}
		})

		It("should work when the second argument is an alias of the caller", func() {
			trials := 1000
			maxDegree := 20

			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				c.Sub(a, b)
				b.Sub(a, b)

				Expect(b.Eq(c)).To(BeTrue())
			}
		})

		It("should work when the first argument is an alias of the second", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)
			d := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.Set(a)
				c.Sub(a, b)
				d.Sub(a, a)

				Expect(d.Eq(c)).To(BeTrue())
			}
		})

		It("should work when the caller and both arguments are aliases of each other", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.Set(a)
				c.Sub(a, b)
				a.Sub(a, a)

				Expect(a.Eq(c)).To(BeTrue())
			}
		})
	})

	Context("when negating polynomials", func() {
		It("should satisfy the defining relation", func() {
			trials := 1000
			maxDegree := 20

			var neg secp256k1.Fn
			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.Neg(a)

				for j := 0; j <= b.Degree(); j++ {
					neg.Negate(a.Coefficient(j))
					Expect(b.Coefficient(j).Eq(&neg)).To(BeTrue())
				}
			}
		})
	})

	Context("when multiplying polynomials", func() {
		It("should satisfy the defining relation", func() {
			trials := 1000
			maxDegree := 20

			var term secp256k1.Fn
			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(2 * (maxDegree + 1))
			d := NewWithCapacity(2 * (maxDegree + 1))

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				c.Mul(a, b)

				// Manually calculate the multiplication
				d = d[:degreeA+degreeB+1]
				for j := 0; j <= d.Degree(); j++ {
					*d.Coefficient(j) = zero
				}
				for j := 0; j <= a.Degree(); j++ {
					for k := 0; k <= b.Degree(); k++ {
						term.Mul(a.Coefficient(j), b.Coefficient(k))
						d.Coefficient(j+k).Add(d.Coefficient(j+k), &term)
					}
				}

				Expect(c.Eq(d)).To(BeTrue())
			}
		})

		It("should work when either argument is the zero polynomial", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			z := NewWithCapacity(1)
			z.Zero()

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)

				b.Mul(a, z)
				Expect(b.IsZero()).To(BeTrue())

				b.Mul(z, a)
				Expect(b.IsZero()).To(BeTrue())
			}
		})

		It("should work when the first argument is an alias of the caller", func() {
			trials := 1000
			maxDegree := 20

			var degreeA, degreeB int

			a := NewWithCapacity(2 * (maxDegree + 1))
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(2 * (maxDegree + 1))

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				c.Mul(a, b)
				a.Mul(a, b)

				Expect(a.Eq(c)).To(BeTrue())
			}
		})

		It("should work when the second argument is an alias of the caller", func() {
			trials := 1000
			maxDegree := 20

			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(2 * (maxDegree + 1))
			c := NewWithCapacity(2 * (maxDegree + 1))

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				c.Mul(a, b)
				b.Mul(a, b)

				Expect(b.Eq(c)).To(BeTrue())
			}
		})

		It("should work when the first argument is an alias of the second", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(2 * (maxDegree + 1))
			d := NewWithCapacity(2 * (maxDegree + 1))

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.Set(a)
				c.Mul(a, b)
				d.Mul(a, a)

				Expect(d.Eq(c)).To(BeTrue())
			}
		})

		It("should give an incorrect result when the caller and both arguments are aliases of each other", func() {
			trials := 1000
			maxDegree := 20

			var degree int

			a := NewWithCapacity(2 * (maxDegree + 1))
			b := NewWithCapacity(maxDegree + 1)
			c := NewWithCapacity(2 * (maxDegree + 1))

			for i := 0; i < trials; i++ {
				degree = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degree)
				b.Set(a)
				c.Mul(a, b)
				a.Mul(a, a)

				if degree == 0 {
					Expect(a.Eq(c)).To(BeTrue())
				} else {
					Expect(a.Eq(c)).To(BeFalse())
				}
			}
		})
	})

	Context("when doing polynomial division", func() {
		Specify("the defining relation should hold", func() {
			trials := 1000
			maxDegree := 20

			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			q := NewWithCapacity(maxDegree + 1)
			r := NewWithCapacity(maxDegree + 1)
			aRecon := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(degreeA + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				if b.IsZero() {
					continue
				}

				Divide(a, b, &q, &r)
				aRecon.Mul(q, b)
				aRecon.Add(aRecon, r)

				Expect(aRecon.Eq(a)).To(BeTrue())
			}
		})

		It("should give the trivial result when deg(a) < deb(b)", func() {
			trials := 1000
			maxDegree := 20

			var degreeA, degreeB int

			a := NewWithCapacity(maxDegree + 1)
			b := NewWithCapacity(maxDegree + 1)
			q := NewWithCapacity(maxDegree + 1)
			r := NewWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degreeB = rand.Intn(maxDegree-1) + 2
				degreeA = rand.Intn(degreeB-1) + 1
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				if b.IsZero() {
					continue
				}

				Divide(a, b, &q, &r)

				Expect(q.IsZero()).To(BeTrue())
				Expect(r.Eq(a)).To(BeTrue())
			}
		})
	})
})

func addCheckDegree(a, b, c Poly) bool {
	degreeA, degreeB := a.Degree(), b.Degree()
	var coeff secp256k1.Fn
	if degreeA != degreeB {
		return c.Degree() == shamirutil.Max(degreeA, degreeB)
	}

	// Account for the case that some leading coefficients
	// cancelled eachother
	if c.Degree() != degreeA {
		for i := c.Degree() + 1; i <= degreeA; i++ {
			coeff.Add(&a[i], &b[i])
			if !coeff.IsZero() {
				return false
			}
		}

		return true
	}

	return c.Degree() == degreeA
}

func subCheckDegree(a, b, c Poly) bool {
	degreeA, degreeB := a.Degree(), b.Degree()
	if degreeA != degreeB {
		return c.Degree() == shamirutil.Max(degreeA, degreeB)
	}

	// Account for the case that some leading coefficients
	// cancelled eachother
	if c.Degree() != degreeA {
		for i := c.Degree() + 1; i <= degreeA; i++ {
			if !a.Coefficient(i).Eq(b.Coefficient(i)) {
				return false
			}
		}

		return true
	}

	return c.Degree() == degreeA
}

func BenchmarkPolyAdd(b *testing.B) {
	n := 100
	poly1 := NewWithCapacity(n)
	poly2 := NewWithCapacity(n)
	polySum := NewWithCapacity(n)

	polyutil.SetRandomPolynomial(&poly1, n-1)
	polyutil.SetRandomPolynomial(&poly2, n-1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		polySum.Add(poly1, poly2)
	}
}

func BenchmarkPolyMul(b *testing.B) {
	n := 50
	poly1 := NewWithCapacity(n)
	poly2 := NewWithCapacity(n)
	polyProd := NewWithCapacity(2 * n)

	polyutil.SetRandomPolynomial(&poly1, n-1)
	polyutil.SetRandomPolynomial(&poly2, n-1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		polyProd.Mul(poly1, poly2)
	}
}

func BenchmarkPolyInterpolate(b *testing.B) {
	n := 100
	indices := shamirutil.RandomIndices(n)
	values := shamirutil.RandomIndices(n)
	poly := NewWithCapacity(n)
	interp := NewInterpolator(indices)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		interp.Interpolate(values, &poly)
	}
}
