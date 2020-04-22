package curve_test

import (
	"github.com/renproject/surge"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir/curve"
)

var _ = Describe("Secp256k1 Curve", func() {
	Context("Binary marshaling", func() {
		It("should be the same after marshalling to and from binary", func() {
			trials := 1000
			var p1, p2 Point
			var bs [64]byte

			p2 = New()

			for i := 0; i < trials; i++ {
				p1 = Random()
				p1.GetBytes(bs[:])
				p2.SetBytes(bs[:])
				Expect(p1.Eq(&p2)).To(BeTrue())
			}
		})

		It("should be the same after marshalling and unmarshalling with surge", func() {
			trials := 1000
			var p1, p2 Point

			p2 = New()

			for i := 0; i < trials; i++ {
				p1 = Random()
				bs, err := surge.ToBinary(&p1)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(bs[:], &p2)
				Expect(p1.Eq(&p2)).To(BeTrue())
			}
		})
	})
})
