package shamir_test

import (
	"math/rand"
	"testing"
	"time"

	. "."

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/renproject/secp256k1-go"
)

var _ = Describe("Shamir Secret Sharing", func() {
	rand.Seed(time.Now().UnixNano())

	Context("when sharing and reconstructing a secret", func() {
		It("should reconstruct to the same shared secret", func() {
			trials := 100
			n := 20
			var k int

			indices := sequentialIndices(n)
			shares := make(Shares, n)
			sharer := NewSharer(indices)
			reconstructor := NewReconstructor(indices)

			var secret secp256k1.Secp256k1N
			for i := 0; i < trials; i++ {
				k = rand.Intn(n) + 1
				secret = secp256k1.RandomSecp256k1N()
				err := sharer.Share(&shares, secret, k)
				Expect(err).ToNot(HaveOccurred())
				shuffle(shares)
				recons, err := reconstructor.Open(shares[:k+rand.Intn(n-k+1)])

				Expect(err).ToNot(HaveOccurred())
				Expect(recons.Eq(&secret)).To(BeTrue())
			}
		})
	})

	Context("when creating shares from a secret", func() {
		Specify("there should be the right number of shares and they should be well formed", func() {
			trials := 100
			n := 20
			var k int

			indices := sequentialIndices(n)
			shares := make(Shares, n)
			sharer := NewSharer(indices)

			for i := 0; i < trials; i++ {
				k = rand.Intn(n) + 1
				secret := secp256k1.RandomSecp256k1N()
				err := sharer.Share(&shares, secret, k)

				Expect(err).ToNot(HaveOccurred())
				Expect(len(shares)).To(Equal(n))
				for i, share := range shares {
					ind := share.Index()
					Expect(ind.Uint64()).To(Equal(uint64(i + 1)))
				}
			}
		})

		It("should not contruct shares when k is too high", func() {
			trials := 100
			n := 20
			maxK := 100

			indices := sequentialIndices(n)
			shares := make(Shares, n)
			sharer := NewSharer(indices)

			for i := 0; i < trials; i++ {
				k := rand.Intn(maxK-n) + n + 1
				secret := secp256k1.RandomSecp256k1N()
				err := sharer.Share(&shares, secret, k)

				Expect(err).To(HaveOccurred())
			}
		})

		It("should panic if the destination slice capacity is too small", func() {
			trials := 100
			n := 20

			indices := sequentialIndices(n)
			sharer := NewSharer(indices)

			for i := 0; i < trials; i++ {
				k := rand.Intn(n) + 1
				secret := secp256k1.RandomSecp256k1N()
				shares := make(Shares, rand.Intn(n))
				Expect(func() { sharer.Share(&shares, secret, k) }).Should(Panic())
			}
		})
	})

	Context("when reconstructing a secret from shares", func() {
		It("should reconstruct without error when all shares have valid indices", func() {
			trials := 100
			n := 20
			var k int

			indices := sequentialIndices(n)
			reconstructor := NewReconstructor(indices)
			shares := make(Shares, n)
			zero := secp256k1.ZeroSecp256k1N()

			for i := range shares {
				shares[i] = NewShare(indices[i], zero)
			}

			for i := 0; i < trials; i++ {
				k = rand.Intn(n) + 1
				shuffle(shares)
				_, err := reconstructor.Open(shares[:k+rand.Intn(n-k+1)])

				Expect(err).ToNot(HaveOccurred())
			}
		})

		It("should not open when the number of shares is too high", func() {
			trials := 100
			n := 20
			maxNumShares := 100

			indices := sequentialIndices(n)
			reconstructor := NewReconstructor(indices)
			shares := make(Shares, maxNumShares)

			for i := 0; i < trials; i++ {
				numShares := rand.Intn(maxNumShares-n) + n + 1
				shares = shares[:numShares]
				secret, err := reconstructor.Open(shares)

				Expect(err).To(HaveOccurred())
				Expect(secret.IsZero()).To(BeTrue())
			}
		})

		It("should not open when there is a share with an out of range index", func() {
			trials := 100
			n := 20

			indices := sequentialIndices(n)
			reconstructor := NewReconstructor(indices)
			shares := make(Shares, n)
			zero := secp256k1.ZeroSecp256k1N()

			for i := range shares {
				shares[i] = NewShare(indices[i], zero)
			}

			for i := 0; i < trials; i++ {
				// Change one of the indices. It is possible that the random
				// index is actually valid, but the chance of this happening is
				// negligible
				shares[rand.Intn(n)] = NewShare(secp256k1.RandomSecp256k1N(), zero)
				secret, err := reconstructor.Open(shares)

				Expect(err).To(HaveOccurred())
				Expect(secret.IsZero()).To(BeTrue())
			}
		})

		It("should not open when two shares have the same index", func() {
			trials := 100
			n := 20

			indices := sequentialIndices(n)
			reconstructor := NewReconstructor(indices)
			shares := make(Shares, n)
			one := secp256k1.OneSecp256k1N()
			var newInd secp256k1.Secp256k1N

			for i := range shares {
				shares[i] = NewShare(indices[i], one)
			}

			for i := 0; i < trials; i++ {
				pos := rand.Intn(n)
				newInd.Set(&one)
				newInd.MulInt(rand.Intn(n) + 1)
				for newInd.Uint64() == uint64(pos+1) {
					newInd.Set(&one)
					newInd.MulInt(rand.Intn(n) + 1)
				}
				shares[pos] = NewShare(newInd, one)
				secret, err := reconstructor.Open(shares)

				Expect(err).To(HaveOccurred())
				Expect(secret.IsZero()).To(BeTrue())
			}
		})
	})

	Context("when doing a checked reconstruction of a secret from shares", func() {
		It("should give an error if there are not enough shares, and no error otherwise", func() {
			trials := 100
			n := 20
			var k, lowK, highK int

			indices := sequentialIndices(n)
			reconstructor := NewReconstructor(indices)
			shares := make(Shares, n)
			zero := secp256k1.ZeroSecp256k1N()

			for i := range shares {
				shares[i] = NewShare(indices[i], zero)
			}

			for i := 0; i < trials; i++ {
				k = rand.Intn(n) + 1
				lowK = rand.Intn(k)
				highK = rand.Intn(n-k+1) + k

				_, err := reconstructor.CheckedOpen(shares[:lowK], k)
				Expect(err).To(HaveOccurred())

				_, err = reconstructor.CheckedOpen(shares[:highK], k)
				Expect(err).ToNot(HaveOccurred())
			}
		})
	})
})

func BenchmarkShare(b *testing.B) {
	n := 100
	k := 33

	indices := sequentialIndices(n)
	shares := make(Shares, n)
	sharer := NewSharer(indices)
	secret := secp256k1.RandomSecp256k1N()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sharer.Share(&shares, secret, k)
	}
}

func BenchmarkOpen(b *testing.B) {
	n := 100
	k := 33

	indices := sequentialIndices(n)
	shares := make(Shares, n)
	sharer := NewSharer(indices)
	reconstructor := NewReconstructor(indices)
	secret := secp256k1.RandomSecp256k1N()
	_ = sharer.Share(&shares, secret, k)
	shuffle(shares)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = reconstructor.Open(shares[:k])
	}
}

func sequentialIndices(n int) []secp256k1.Secp256k1N {
	indices := make([]secp256k1.Secp256k1N, n)
	one := secp256k1.OneSecp256k1N()
	for i := range indices {
		indices[i].Set(&one)
		indices[i].MulInt(i + 1)
	}

	return indices
}

func shuffle(shares Shares) {
	rand.Shuffle(len(shares), func(i, j int) {
		shares[i], shares[j] = shares[j], shares[i]
	})
}
