package rs_test

import (
	"math/rand"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir/rs"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/eea/eeautil"
	"github.com/renproject/shamir/poly"
	"github.com/renproject/shamir/poly/polyutil"
	"github.com/renproject/shamir/shamirutil"
)

var _ = Describe("Reed-Solomon Decoding", func() {
	Context("when decoding messages", func() {
		It("should recover the polynomial when there are no errors", func() {
			trials := 100
			maxN := 20
			maxDegree := maxN - 1
			var n, k int

			poly := poly.NewWithCapacity(maxDegree + 1)
			values := make([]secp256k1.Fn, maxN)

			for i := 0; i < trials; i++ {
				n = rand.Intn(maxN) + 1
				k = rand.Intn(n) + 1
				indices := shamirutil.RandomIndices(n)
				decoder := NewDecoder(indices, k)

				polyutil.SetRandomPolynomial(&poly, k-1)
				values = values[:n]
				for j, index := range indices {
					values[j] = poly.Evaluate(index)
				}
				reconstructed, ok := decoder.Decode(values)
				errors := decoder.ErrorIndices()

				Expect(ok).To(BeTrue())
				Expect(reconstructed.Eq(poly)).To(BeTrue())
				Expect(errors).To(BeNil())
			}
		})

		It("should recover the polynomial when there are fewer than t errors", func() {
			trials := 100
			maxN := 20
			maxDegree := maxN - 1
			var n, k, t int

			poly := poly.NewWithCapacity(maxDegree + 1)
			values := make([]secp256k1.Fn, maxN)
			l := make([]int, maxN/2)

			for i := 0; i < trials; i++ {
				n = rand.Intn(maxN-2) + 3
				k = rand.Intn(n-2) + 1
				t = (n - k) / 2
				indices := shamirutil.RandomIndices(n)
				decoder := NewDecoder(indices, k)

				polyutil.SetRandomPolynomial(&poly, k-1)
				values = values[:n]
				for j, index := range indices {
					values[j] = poly.Evaluate(index)
				}

				// Add errors to the values
				e := rand.Intn(t) + 1
				eeautil.RandomSubset(&l, e, n)
				addErrors(values[:], l)

				reconstructed, ok := decoder.Decode(values[:])

				Expect(ok).To(BeTrue())
				Expect(reconstructed.Eq(poly)).To(BeTrue())

				// The errors should be correctly identified
				Expect(len(decoder.ErrorIndices())).To(Equal(e))
				for _, index := range decoder.ErrorIndices() {
					listIndex := 0
					for !indices[listIndex].Eq(&index) {
						listIndex++
					}
					Expect(eeautil.Contains(l, listIndex)).To(BeTrue())
				}
			}
		})

		It("should not recover the polynomial when there are more than t errors", func() {
			trials := 100
			maxN := 20
			maxDegree := maxN - 1
			var n, k, t int

			poly := poly.NewWithCapacity(maxDegree + 1)
			values := make([]secp256k1.Fn, maxN)
			l := make([]int, maxN/2)

			for i := 0; i < trials; i++ {
				n = rand.Intn(maxN-2) + 3
				k = rand.Intn(n-2) + 1
				t = (n - k) / 2
				indices := shamirutil.RandomIndices(n)
				decoder := NewDecoder(indices, k)

				polyutil.SetRandomPolynomial(&poly, k-1)
				values = values[:n]
				for j, index := range indices {
					values[j] = poly.Evaluate(index)
				}

				// Add errors to the values
				e := rand.Intn(n-t) + 1 + t
				eeautil.RandomSubset(&l, e, n)
				addErrors(values[:], l)

				reconstructed, ok := decoder.Decode(values[:])

				Expect(ok).To(BeFalse())
				Expect(reconstructed).To(BeNil())
			}
		})

		It("should return a nil error slice when nothing has been decoded", func() {
			const n int = 15
			const k int = 6

			indices := [n]secp256k1.Fn{}

			for i := range indices {
				indices[i].SetU16(uint16(i + 1))
			}

			decoder := NewDecoder(indices[:], k)
			Expect(decoder.ErrorIndices()).To(BeNil())
		})
	})
})

func BenchmarkDecodeNoErrors(b *testing.B) {
	const n int = 100
	const k int = 34
	degree := k - 1

	poly := poly.NewWithCapacity(degree + 1)
	values := [n]secp256k1.Fn{}
	indices := [n]secp256k1.Fn{}

	for i := range indices {
		indices[i].SetU16(uint16(i + 1))
	}
	polyutil.SetRandomPolynomial(&poly, degree)

	decoder := NewDecoder(indices[:], k)

	for j, index := range indices {
		values[j] = poly.Evaluate(index)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decoder.Decode(values[:])
	}
}

func BenchmarkDecodeRecoverableErrors(b *testing.B) {
	const n int = 100
	const k int = 34
	t := (n - k) / 2
	degree := k - 1

	poly := poly.NewWithCapacity(degree + 1)
	values := [n]secp256k1.Fn{}
	indices := [n]secp256k1.Fn{}
	l := make([]int, t)

	for i := range indices {
		indices[i].SetU16(uint16(i + 1))
	}
	polyutil.SetRandomPolynomial(&poly, degree)

	decoder := NewDecoder(indices[:], k)

	for j, index := range indices {
		values[j] = poly.Evaluate(index)
	}

	// Add errors to the values
	e := rand.Intn(t) + 1
	eeautil.RandomSubset(&l, e, n)
	addErrors(values[:], l)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decoder.Decode(values[:])
	}
}

func addErrors(values []secp256k1.Fn, subset []int) {
	for _, i := range subset {
		values[i] = secp256k1.RandomFn()
	}
}
