package curve_test

import (
	"bytes"
	"math/rand"

	"github.com/renproject/surge"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir/curve"
)

var _ = Describe("Secp256k1 Curve", func() {

	//
	// Marshalling
	//
	// The important properties that we want of marshalling and unmarshalling
	// are:
	//
	//	1. Marshalling a curve point and then unmarshalling this data into a
	//	curve point should result in the same curve point.
	//	2. Unmarshalling arbitrary data into a curve point should only succeed
	//	if the data is of the correct length and represents a valid curve
	//	point.

	Context("Marshaling", func() {
		trials := 1000
		var bs [64]byte
		var p, p1, p2 Point

		BeforeEach(func() {
			p, p1, p2 = New(), New(), New()
		})

		It("should be the same after marshalling to and from binary", func() {
			for i := 0; i < trials; i++ {
				p1 = Random()
				p1.GetBytes(bs[:])
				p2.SetBytes(bs[:])
				Expect(p1.Eq(&p2)).To(BeTrue())
			}
		})

		It("should be the same after marshalling and unmarshalling with surge", func() {
			for i := 0; i < trials; i++ {
				p1 = Random()
				bs, err := surge.ToBinary(&p1)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(bs[:], &p2)
				Expect(p1.Eq(&p2)).To(BeTrue())
			}
		})

		Specify("unmarhsalling should return an error if the remaining bytes is less than 64", func() {
			for i := 0; i < trials; i++ {
				buf := bytes.NewBuffer(bs[:])
				max := rand.Intn(64)
				m, err := p.Unmarshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(max))
			}
		})

		Specify("unmarhsalling should return an error if the reader doesn't have enough data", func() {
			for i := 0; i < trials; i++ {
				max := rand.Intn(64)
				buf := bytes.NewBuffer(bs[:max])
				m, err := p.Unmarshal(buf, 64)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(64 - max))
			}
		})

		Specify("unmarhsalling should return an error if the data doesn't represent a curve point", func() {
			for i := 0; i < trials; i++ {
				// The probability that a random 64 bytes will represent a
				// point on the curve is negligible.
				rand.Read(bs[:])
				buf := bytes.NewBuffer(bs[:])
				m, err := p.Unmarshal(buf, 64)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(0))
			}
		})
	})

	//
	// Miscellaneous Tests
	//

	Context("Constants", func() {
		Specify("PointSizeBytes should have correct value", func() {
			p := New()
			Expect(PointSizeBytes).To(Equal(p.SizeHint()))
		})
	})
})
