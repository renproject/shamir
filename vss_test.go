package shamir_test

import (
	"math/rand"

	. "."

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/renproject/secp256k1-go"
)

var _ = Describe("Verifiable secret sharing", func() {
	Context("when checking the validity of shares", func() {
		Specify("valid share should be valid", func() {
			trials := 100
			n := 20
			var k int

			indices := sequentialIndices(n)
			shares := make(Shares, n)
			c := NewCommitmentWithCapacity(n)
			vssharer := NewVSSharer(indices)

			var secret secp256k1.Secp256k1N
			for i := 0; i < trials; i++ {
				k = rand.Intn(n) + 1
				k = 1
				secret = secp256k1.RandomSecp256k1N()
				err := vssharer.Share(&shares, &c, secret, k)
				Expect(err).ToNot(HaveOccurred())

				for _, share := range shares {
					Expect(c.IsValid(&share)).To(BeTrue())
				}
			}
		})
	})
})
