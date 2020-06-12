package curve_test

import (
	"bytes"
	"math/rand"

	"github.com/renproject/secp256k1-go"
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
		var bs [PointSizeBytes]byte
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

		Specify("unmarshalling should return an error if the remaining bytes is less than PointSizeBytes", func() {
			for i := 0; i < trials; i++ {
				buf := bytes.NewBuffer(bs[:])
				max := rand.Intn(PointSizeBytes)
				m, err := p.Unmarshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(max))
			}
		})

		Specify("unmarshalling should return an error if the reader doesn't have enough data", func() {
			for i := 0; i < trials; i++ {
				max := rand.Intn(PointSizeBytes)
				buf := bytes.NewBuffer(bs[:max])
				m, err := p.Unmarshal(buf, PointSizeBytes)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(PointSizeBytes - max))
			}
		})

		Specify("unmarshalling should return an error if the data doesn't represent a curve point", func() {
			for i := 0; i < trials; i++ {
				// The probability that a random 65 bytes will represent a
				// point on the curve is negligible.
				// Also mark the point as NOT the point at infinity
				rand.Read(bs[:])
				bs[PointSizeBytes-1] = 0

				buf := bytes.NewBuffer(bs[:])
				m, err := p.Unmarshal(buf, PointSizeBytes)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(0))
			}
		})

		Specify("marshal and unmarshal the point at infinity", func() {
			for i := 0; i < trials; i++ {
				p1 = Infinity()
				p1.GetBytes(bs[:])
				p2.SetBytes(bs[:])
				Expect(p2.Eq(&p1)).To(BeTrue())
				Expect(p2.IsInfinity()).To(BeTrue())
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

	//
	// Point at infinity
	//

	Context("Point at infinity", func() {
		Specify("Point at infinity is on the curve", func() {
			p := Infinity()
			Expect(p.IsOnCurve()).To(BeTrue())
		})

		Specify("Point at infinity is printed appropriately", func() {
			p := Infinity()
			Expect(p.String()).To(Equal("Infinity"))
		})

		Specify("Adding a point to the point of infinity", func() {
			p := Infinity()
			q := Random()

			r := New()
			r.Add(&p, &q)
			Expect(r.Eq(&q)).To(BeTrue())

			r.Add(&q, &p)
			Expect(r.Eq(&q)).To(BeTrue())
		})

		Specify("Scaling a point at infinity", func() {
			var bs [32]byte
			q := secp256k1.RandomSecp256k1N()
			q.GetB32(bs[:])
			p := Infinity()

			r := New()
			r.Scale(&p, bs)
			Expect(r.IsInfinity()).To(BeTrue())
		})

		Specify("Scaling a point with zero exponent", func() {
			var bs [32]byte
			p := Random()

			r := New()
			r.Scale(&p, bs)
			Expect(r.IsInfinity()).To(BeTrue())
		})

		Specify("Scaling the generator with zero exponent", func() {
			var bs [32]byte

			r := New()
			r.BaseExp(bs)
			Expect(r.IsInfinity()).To(BeTrue())
		})
	})
})
