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
	h := RandomCurvePoint()

	Context("when checking the validity of shares", func() {
		Specify("valid share should be valid", func() {
			trials := 20
			n := 20
			var k int

			indices := sequentialIndices(n)
			vshares := make(VerifiableShares, n)
			c := NewCommitmentWithCapacity(n)
			vssharer := NewVSSharer(indices, h)
			checker := NewVSSChecker(h)

			var secret secp256k1.Secp256k1N
			for i := 0; i < trials; i++ {
				k = rand.Intn(n) + 1
				secret = secp256k1.RandomSecp256k1N()
				err := vssharer.Share(&vshares, &c, secret, k)
				Expect(err).ToNot(HaveOccurred())

				for _, share := range vshares {
					Expect(checker.IsValid(&c, &share)).To(BeTrue())
				}
			}
		})

		Specify("invalid share should be detected", func() {
			trials := 20
			n := 20
			var k, badInd int

			indices := sequentialIndices(n)
			vshares := make(VerifiableShares, n)
			c := NewCommitmentWithCapacity(n)
			vssharer := NewVSSharer(indices, h)
			checker := NewVSSChecker(h)

			var secret secp256k1.Secp256k1N
			for i := 0; i < trials; i++ {
				k = rand.Intn(n) + 1
				secret = secp256k1.RandomSecp256k1N()
				err := vssharer.Share(&vshares, &c, secret, k)
				Expect(err).ToNot(HaveOccurred())

				// Change one of the shares to be invalid
				badInd = rand.Intn(n)
				vshares[badInd] = NewVerifiableShare(
					NewShare(secp256k1.RandomSecp256k1N(), indices[badInd]),
					secp256k1.RandomSecp256k1N(),
				)

				for i, share := range vshares {
					Expect(checker.IsValid(&c, &share)).To(Equal(i != badInd))
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
				vshares1 := make(VerifiableShares, n)
				vshares2 := make(VerifiableShares, n)
				vsharesSummed := make(VerifiableShares, n)
				c1 := NewCommitmentWithCapacity(n)
				c2 := NewCommitmentWithCapacity(n)
				cSummed := NewCommitmentWithCapacity(n)
				vssharer := NewVSSharer(indices, h)
				checker := NewVSSChecker(h)

				var secret1, secret2 secp256k1.Secp256k1N
				for i := 0; i < trials; i++ {
					k = rand.Intn(n) + 1
					secret1 = secp256k1.RandomSecp256k1N()
					secret2 = secp256k1.RandomSecp256k1N()
					_ = vssharer.Share(&vshares1, &c1, secret1, k)
					_ = vssharer.Share(&vshares2, &c2, secret2, k)

					// Create the shares for the sum
					cSummed.Add(&c1, &c2)
					for i := range vsharesSummed {
						vsharesSummed[i].Add(&vshares1[i], &vshares2[i])
					}

					// The shares should be valid
					for _, share := range vsharesSummed {
						Expect(checker.IsValid(&cSummed, &share)).To(BeTrue())
					}

					// A perturbed share should be identified as invalid
					badInd := rand.Intn(n)
					badShare := NewVerifiableShare(
						NewShare(secp256k1.RandomSecp256k1N(), indices[badInd]),
						secp256k1.RandomSecp256k1N(),
					)
					Expect(checker.IsValid(&cSummed, &badShare)).To(BeFalse())
				}
			})
		})

		Context("when scaling a commitment", func() {
			Specify("the resulting commitment should correspond to the scaling of the shares", func() {
				trials := 20
				n := 20
				var k int

				indices := sequentialIndices(n)
				vshares := make(VerifiableShares, n)
				vsharesScaled := make(VerifiableShares, n)
				c := NewCommitmentWithCapacity(n)
				cScaled := NewCommitmentWithCapacity(n)
				vssharer := NewVSSharer(indices, h)
				checker := NewVSSChecker(h)

				var secret, scale secp256k1.Secp256k1N
				for i := 0; i < trials; i++ {
					k = rand.Intn(n) + 1
					secret = secp256k1.RandomSecp256k1N()
					scale = secp256k1.RandomSecp256k1N()
					_ = vssharer.Share(&vshares, &c, secret, k)

					// Create the scaled shares
					cScaled.Scale(&c, &scale)
					for i := range vsharesScaled {
						vsharesScaled[i].Scale(&vshares[i], &scale)
					}

					// The shares should be valid
					for _, share := range vsharesScaled {
						Expect(checker.IsValid(&cScaled, &share)).To(BeTrue())
					}

					// A perturbed share should be identified as invalid
					badInd := rand.Intn(n)
					badShare := NewVerifiableShare(
						NewShare(secp256k1.RandomSecp256k1N(), indices[badInd]),
						secp256k1.RandomSecp256k1N(),
					)
					Expect(checker.IsValid(&cScaled, &badShare)).To(BeFalse())
				}
			})
		})
	})
})

func BenchmarkVSShare(b *testing.B) {
	n := 100
	k := 33
	h := RandomCurvePoint()

	indices := sequentialIndices(n)
	vshares := make(VerifiableShares, n)
	c := NewCommitmentWithCapacity(n)
	vssharer := NewVSSharer(indices, h)
	secret := secp256k1.RandomSecp256k1N()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = vssharer.Share(&vshares, &c, secret, k)
	}
}

func BenchmarkVSSVerify(b *testing.B) {
	n := 100
	k := 33
	h := RandomCurvePoint()

	indices := sequentialIndices(n)
	vshares := make(VerifiableShares, n)
	c := NewCommitmentWithCapacity(n)
	vssharer := NewVSSharer(indices, h)
	checker := NewVSSChecker(h)
	secret := secp256k1.RandomSecp256k1N()
	_ = vssharer.Share(&vshares, &c, secret, k)
	ind := rand.Intn(100)
	share := vshares[ind]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.IsValid(&c, &share)
	}
}
