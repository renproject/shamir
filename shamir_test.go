package shamir_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/renproject/secp256k1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir"
	. "github.com/renproject/shamir/shamirutil"
)

//
// Let n and k be given where n >= k. Then Shamir secret sharing with these
// parameters should satisfy the following properties:
//
//	1. Any element in the field can be shared such that n shares are produced.
//	Further, any subset of k or more of these shares can be combined to
//	reconstruct the shared element (secret).
//
//	2. The shares are homomorphically additive. This means that if two secrets
//	are shared, then adding the respective shares (shares with the same index
//	get added) results in a new sharing, and the secret value for this sharing
//	is the sum of the two original secrets.
//
//	3. The shares are homomorphic with regard to scaling. This means that if a
//	secret is shared, then multiplying each share by the same scalar results in
//	a new sharing, and the secret value for this sharing is the product of the
//	original secret and the scalar.
//
var _ = Describe("Shamir Secret Sharing", func() {
	rand.Seed(time.Now().UnixNano())

	Context("Sharing consistency (1)", func() {
		trials := 100
		n := 20

		var k int
		var secret secp256k1.Fn

		Specify("any qualified subset can reconstruct the secret correctly", func() {
			indices := RandomIndices(n)
			shares := make(Shares, n)

			for i := 0; i < trials; i++ {
				k = RandRange(1, n)
				secret = secp256k1.RandomFn()

				err := ShareSecret(&shares, indices, secret, k)
				Expect(err).ToNot(HaveOccurred())

				recon := Open(shares)
				Expect(recon.Eq(&secret)).To(BeTrue())

				Expect(SharesAreConsistent(shares, k)).To(BeTrue())
			}
		})
	})

	Context("Homomorphic under addition (2)", func() {
		trials := 100
		n := 20

		var k1, k2, kmax int
		var secret1, secret2, secretSummed secp256k1.Fn

		Specify("summed shares should be a consistent sharing of the sum of the secrets", func() {
			indices := RandomIndices(n)
			shares1 := make(Shares, n)
			shares2 := make(Shares, n)
			sharesSummed := make(Shares, n)

			for i := 0; i < trials; i++ {
				k1 = RandRange(1, n)
				k2 = RandRange(1, n)
				kmax = Max(k1, k2)
				secret1 = secp256k1.RandomFn()
				secret2 = secp256k1.RandomFn()
				secretSummed.Add(&secret1, &secret2)

				_ = ShareSecret(&shares1, indices, secret1, k1)
				_ = ShareSecret(&shares2, indices, secret2, k2)

				// Construct the summed shares
				for i := range sharesSummed {
					sharesSummed[i].Add(&shares1[i], &shares2[i])
				}

				recon := Open(sharesSummed)
				Expect(recon.Eq(&secretSummed)).To(BeTrue())

				Expect(SharesAreConsistent(sharesSummed, kmax)).To(BeTrue())
			}
		})
	})

	Context("Homomorphic under scaling (3)", func() {
		trials := 100
		n := 20

		var k int
		var secret, scale, secretScaled secp256k1.Fn

		Specify(
			"scaled shares should be a consistent sharing of the product of the secret and the scalar",
			func() {
				indices := RandomIndices(n)
				shares := make(Shares, n)
				sharesScaled := make(Shares, n)

				for i := 0; i < trials; i++ {
					k = RandRange(1, n)
					secret = secp256k1.RandomFn()
					scale = secp256k1.RandomFn()
					secretScaled.Mul(&secret, &scale)

					_ = ShareSecret(&shares, indices, secret, k)

					// Construct the summed shares
					for i := range sharesScaled {
						sharesScaled[i].Scale(&shares[i], &scale)
					}

					recon := Open(sharesScaled)
					Expect(recon.Eq(&secretScaled)).To(BeTrue())

					Expect(SharesAreConsistent(sharesScaled, k)).To(BeTrue())
				}
			},
		)
	})

	//
	// Share tests
	//

	Context("Shares", func() {
		trials := 100

		var bs [ShareSize]byte
		var share, share1, share2, shareSum, shareScale Share

		It("should correctly identify shares that have the same index", func() {
			var index secp256k1.Fn
			var share Share

			for i := 0; i < trials; i++ {
				index = secp256k1.RandomFn()
				share.Index = index
				share.Value = secp256k1.RandomFn()
				Expect(share.IndexEq(&index)).To(BeTrue())

				index = secp256k1.RandomFn()
				Expect(share.IndexEq(&index)).To(BeFalse())
			}
		})

		Specify("adding should add the values and leave the index unchanged", func() {
			var index, value1, value2, sum secp256k1.Fn

			for i := 0; i < trials; i++ {
				index = secp256k1.RandomFn()
				value1 = secp256k1.RandomFn()
				value2 = secp256k1.RandomFn()
				sum.Add(&value1, &value2)

				// The resulting share should have the values added and the
				// same index.
				share1 = NewShare(index, value1)
				share2 = NewShare(index, value2)
				shareSum.Add(&share1, &share2)
				Expect(shareSum.Value.Eq(&sum)).To(BeTrue())
				Expect(shareSum.Index.Eq(&index)).To(BeTrue())

				// Adding two shares with different indices should panic.
				share1 = NewShare(secp256k1.RandomFn(), value1)
				Expect(func() { shareSum.Add(&share1, &share2) }).To(Panic())
			}
		})

		Specify("scaling should multiply the value and leave the index unchanged", func() {
			var scale, value, index, prod secp256k1.Fn

			for i := 0; i < trials; i++ {
				index = secp256k1.RandomFn()
				value = secp256k1.RandomFn()
				scale = secp256k1.RandomFn()
				prod.Mul(&value, &scale)

				// The resulting share should have the value scaled and the
				// same index.
				share = NewShare(index, value)
				shareScale.Scale(&share, &scale)
				Expect(shareScale.Value.Eq(&prod)).To(BeTrue())
				Expect(shareScale.Index.Eq(&index)).To(BeTrue())
			}
		})

		//
		// Marshaling
		//

		It("should be able to unmarshal into an empty struct", func() {
			share1 := NewShare(secp256k1.RandomFn(), secp256k1.RandomFn())
			share2 := Share{}

			_, _, _ = share1.Marshal(bs[:], share1.SizeHint())
			_, m, err := share2.Unmarshal(bs[:], share1.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
			Expect(share1.Eq(&share2)).To(BeTrue())
		})
	})

	//
	// Shares tests
	//

	Context("Shares", func() {
		const maxN = 20
		const maxLen = 4 + maxN*ShareSize
		var bs [maxLen]byte

		shares1 := make(Shares, maxN)
		shares2 := make(Shares, maxN)

		RandomiseShares := func(shares Shares) {
			for i := range shares {
				shares[i] = NewShare(
					secp256k1.RandomFn(),
					secp256k1.RandomFn(),
				)
			}
		}

		SharesAreEq := func(shares1, shares2 Shares) bool {
			if len(shares1) != len(shares2) {
				return false
			}
			for i := range shares1 {
				if !shares1[i].Eq(&shares2[i]) {
					return false
				}
			}
			return true
		}

		It("should be able to unmarshal into an empty struct", func() {
			shares1 = shares1[:maxN]
			RandomiseShares(shares1)
			shares2 = Shares{}

			_, _, _ = shares1.Marshal(bs[:], shares1.SizeHint())
			_, m, err := shares2.Unmarshal(bs[:], shares1.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
			Expect(SharesAreEq(shares1, shares2)).To(BeTrue())
		})
	})

	//
	// Secret sharing tests
	//
	// We will test the three failure branches of creating shares:
	//
	//	1. If k is larger than the number of indices, the function will return
	//	an error.
	//	2. If the destination slice is too small to hold all of the shares, the
	//	function will panic.
	//	3. Any of the indices is the zero element.
	//

	Context("Sharer", func() {
		trials := 100
		const n int = 20

		var indices []secp256k1.Fn

		BeforeEach(func() {
			indices = RandomIndices(n)
		})

		It("should return an error when k is larger than the number of indices (1)", func() {
			maxK := 100
			shares := make(Shares, n)

			for i := 0; i < trials; i++ {
				k := RandRange(n+1, maxK)
				secret := secp256k1.RandomFn()
				err := ShareSecret(&shares, indices, secret, k)

				Expect(err).To(HaveOccurred())
			}
		})

		It("should panic if the destination slice capacity is too small (2)", func() {
			for i := 0; i < trials; i++ {
				k := RandRange(1, n)
				secret := secp256k1.RandomFn()
				shares := make(Shares, rand.Intn(n))
				Expect(func() { ShareSecret(&shares, indices, secret, k) }).Should(Panic())
			}
		})

		It("should panic if one of the indices is the zero element (3)", func() {
			shares := make(Shares, n)

			for i := 0; i < trials; i++ {
				indices = RandomIndices(n)
				k := RandRange(1, n)
				secret := secp256k1.RandomFn()
				indices[rand.Intn(len(indices))].Clear()
				Expect(func() { ShareSecret(&shares, indices, secret, k) }).Should(Panic())
			}
		})
	})

	//
	// Miscellaneous Tests
	//

	Context("Constants", func() {
		Specify("ShareSize should have correct value", func() {
			share := Share{}
			Expect(ShareSize).To(Equal(share.SizeHint()))
		})
	})
})

func BenchmarkShare(b *testing.B) {
	n := 100
	k := 33

	indices := RandomIndices(n)
	shares := make(Shares, n)
	secret := secp256k1.RandomFn()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ShareSecret(&shares, indices, secret, k)
	}
}

func BenchmarkOpen(b *testing.B) {
	n := 100
	k := 33

	indices := RandomIndices(n)
	shares := make(Shares, n)
	secret := secp256k1.RandomFn()
	_ = ShareSecret(&shares, indices, secret, k)
	Shuffle(shares)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Open(shares[:k])
	}
}
