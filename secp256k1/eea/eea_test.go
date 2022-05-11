package eea_test

import (
	"math/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir/secp256k1/eea"

	"github.com/renproject/shamir/secp256k1/poly"
	"github.com/renproject/shamir/secp256k1/poly/polyutil"
)

var _ = Describe("Extended Euclidean Algorithm", func() {
	Context("when running the extended euclidean algorithm", func() {
		Specify("in each step it should satisfy the invariant relation", func() {
			trials := 1000
			maxDegree := 20

			var degreeA, degreeB int

			a := poly.NewWithCapacity(maxDegree + 1)
			b := poly.NewWithCapacity(maxDegree + 1)
			temp1 := poly.NewWithCapacity(2 * (maxDegree + 1))
			temp2 := poly.NewWithCapacity(2 * (maxDegree + 1))
			rem := poly.NewWithCapacity(2 * (maxDegree + 1))
			eea := NewStepperWithCapacity(maxDegree + 1)

			for i := 0; i < trials; i++ {
				degreeA = rand.Intn(maxDegree + 1)
				degreeB = rand.Intn(maxDegree + 1)
				polyutil.SetRandomPolynomial(&a, degreeA)
				polyutil.SetRandomPolynomial(&b, degreeB)
				if b.IsZero() {
					continue
				}
				eea.Init(a, b)

				temp1.Mul(a, *eea.S())
				temp2.Mul(b, *eea.T())
				rem.Add(temp1, temp2)
				Expect(rem.Eq(*eea.Rem())).To(BeTrue())

				for !eea.Step() {
					temp1.Mul(a, *eea.S())
					temp2.Mul(b, *eea.T())
					rem.Add(temp1, temp2)
					Expect(rem.Eq(*eea.Rem())).To(BeTrue())
				}
			}
		})
	})
})
