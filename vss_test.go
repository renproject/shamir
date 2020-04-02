package shamir_test

import (
	"math/rand"
	"testing"

	. "github.com/renproject/shamir"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/renproject/secp256k1-go"
)

var _ = Describe("Verifiable secret sharing", func() {
	Context("when checking the validity of shares", func() {
		Specify("valid share should be valid", func() {
			trials := 20
			n := 20
			var k int

			indices := sequentialIndices(n)
			shares := make(Shares, n)
			c := NewCommitmentWithCapacity(n)
			vssharer := NewVSSharer(indices)

			var secret secp256k1.Secp256k1N
			for i := 0; i < trials; i++ {
				k = rand.Intn(n) + 1
				secret = secp256k1.RandomSecp256k1N()
				err := vssharer.Share(&shares, &c, secret, k)
				Expect(err).ToNot(HaveOccurred())

				for _, share := range shares {
					Expect(c.IsValid(&share)).To(BeTrue())
				}
			}
		})

		Specify("invalid share should be detected", func() {
			trials := 20
			n := 20
			var k, badInd int

			indices := sequentialIndices(n)
			shares := make(Shares, n)
			c := NewCommitmentWithCapacity(n)
			vssharer := NewVSSharer(indices)

			var secret secp256k1.Secp256k1N
			for i := 0; i < trials; i++ {
				k = rand.Intn(n) + 1
				secret = secp256k1.RandomSecp256k1N()
				err := vssharer.Share(&shares, &c, secret, k)
				Expect(err).ToNot(HaveOccurred())

				// Change one of the shares to be invalid
				badInd = rand.Intn(n)
				shares[badInd] = NewShare(secp256k1.RandomSecp256k1N(), indices[badInd])

				for i, share := range shares {
					Expect(c.IsValid(&share)).To(Equal(i != badInd))
				}
			}
		})
	})

	Context("when constructing a new sharing by combining or modifying other sharings", func() {
		Context("when adding two commitments together", func() {
			Specify("the resulting commitment should correspond to the addition of the shares", func() {
				trials := 20
				n := 20
				var k int

				indices := sequentialIndices(n)
				shares1 := make(Shares, n)
				shares2 := make(Shares, n)
				sharesSummed := make(Shares, n)
				c1 := NewCommitmentWithCapacity(n)
				c2 := NewCommitmentWithCapacity(n)
				cSummed := NewCommitmentWithCapacity(n)
				vssharer := NewVSSharer(indices)

				var secret1, secret2 secp256k1.Secp256k1N
				for i := 0; i < trials; i++ {
					k = rand.Intn(n) + 1
					secret1 = secp256k1.RandomSecp256k1N()
					secret2 = secp256k1.RandomSecp256k1N()
					_ = vssharer.Share(&shares1, &c1, secret1, k)
					_ = vssharer.Share(&shares2, &c2, secret2, k)

					// Create the shares for the sum
					for i := range sharesSummed {
						sharesSummed[i].Add(&shares1[i], &shares2[i])
					}
					cSummed.Add(&c1, &c2)

					// The shares should be valid
					for _, share := range sharesSummed {
						Expect(cSummed.IsValid(&share)).To(BeTrue())
					}

					// A perturbed share should be identified as invalid
					badInd := rand.Intn(n)
					badShare := NewShare(secp256k1.RandomSecp256k1N(), indices[badInd])
					Expect(cSummed.IsValid(&badShare)).To(BeFalse())
				}
			})
		})

		Context("when scaling a commitment", func() {
			Specify("the resulting commitment should correspond to the scaling of the shares", func() {
				trials := 20
				n := 20
				var k int

				indices := sequentialIndices(n)
				shares := make(Shares, n)
				sharesScaled := make(Shares, n)
				c := NewCommitmentWithCapacity(n)
				cScaled := NewCommitmentWithCapacity(n)
				vssharer := NewVSSharer(indices)

				var secret, scale secp256k1.Secp256k1N
				for i := 0; i < trials; i++ {
					k = rand.Intn(n) + 1
					secret = secp256k1.RandomSecp256k1N()
					scale = secp256k1.RandomSecp256k1N()
					_ = vssharer.Share(&shares, &c, secret, k)

					// Create the scaled shares
					for i := range sharesScaled {
						sharesScaled[i].Scale(&shares[i], &scale)
					}
					cScaled.Scale(&c, &scale)

					// The shares should be valid
					for _, share := range sharesScaled {
						Expect(cScaled.IsValid(&share)).To(BeTrue())
					}

					// A perturbed share should be identified as invalid
					badInd := rand.Intn(n)
					badShare := NewShare(secp256k1.RandomSecp256k1N(), indices[badInd])
					Expect(cScaled.IsValid(&badShare)).To(BeFalse())
				}
			})
		})
	})
})

func BenchmarkVSShare(b *testing.B) {
	n := 100
	k := 33

	indices := sequentialIndices(n)
	shares := make(Shares, n)
	c := NewCommitmentWithCapacity(n)
	vssharer := NewVSSharer(indices)
	secret := secp256k1.RandomSecp256k1N()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = vssharer.Share(&shares, &c, secret, k)
	}
}

func BenchmarkVSSVerify(b *testing.B) {
	n := 100
	k := 33

	indices := sequentialIndices(n)
	shares := make(Shares, n)
	c := NewCommitmentWithCapacity(n)
	vssharer := NewVSSharer(indices)
	secret := secp256k1.RandomSecp256k1N()
	_ = vssharer.Share(&shares, &c, secret, k)
	ind := rand.Intn(100)
	share := shares[ind]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.IsValid(&share)
	}
}
