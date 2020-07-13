package poly_test

import (
	"math/rand"

	"github.com/renproject/secp256k1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir/poly"
	"github.com/renproject/shamir/poly/polyutil"
	"github.com/renproject/shamir/shamirutil"
)

var _ = Describe("Polynomial interpolation", func() {
	Context("when interpolating polynomials", func() {
		It("should compute the correct interpolating polynomial", func() {
			trials := 100
			var degree int
			const maxPoints int = 15
			var numPoints int

			poly := NewWithCapacity(maxPoints + 1)
			interpPoly := NewWithCapacity(maxPoints + 1)
			values := make([]secp256k1.Fn, maxPoints)

			for i := 0; i < trials; i++ {
				numPoints = rand.Intn(maxPoints) + 1
				degree = rand.Intn(numPoints)

				indices := shamirutil.RandomIndices(numPoints)
				interpolator := NewInterpolator(indices)

				// Generate random polynomial and associated values
				values = values[:numPoints]
				polyutil.SetRandomPolynomial(&poly, degree)

				for j, index := range indices {
					values[j] = poly.Evaluate(index)
				}

				interpolator.Interpolate(values, &interpPoly)
				Expect(interpPoly.Eq(poly)).To(BeTrue())
			}
		})
	})
})
