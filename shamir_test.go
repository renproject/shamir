package shamir_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"

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
			sharer := NewSharer(indices)
			reconstructor := NewReconstructor(indices)

			for i := 0; i < trials; i++ {
				k = RandRange(1, n)
				secret = secp256k1.RandomFn()

				err := sharer.Share(&shares, secret, k)
				Expect(err).ToNot(HaveOccurred())

				recon, err := reconstructor.Open(shares)
				Expect(err).ToNot(HaveOccurred())
				Expect(recon.Eq(&secret)).To(BeTrue())

				Expect(SharesAreConsistent(shares, &reconstructor, k)).To(BeTrue())
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
			sharer := NewSharer(indices)
			reconstructor := NewReconstructor(indices)

			for i := 0; i < trials; i++ {
				k1 = RandRange(1, n)
				k2 = RandRange(1, n)
				kmax = Max(k1, k2)
				secret1 = secp256k1.RandomFn()
				secret2 = secp256k1.RandomFn()
				secretSummed.Add(&secret1, &secret2)

				_ = sharer.Share(&shares1, secret1, k1)
				_ = sharer.Share(&shares2, secret2, k2)

				// Construct the summed shares
				for i := range sharesSummed {
					sharesSummed[i].Add(&shares1[i], &shares2[i])
				}

				recon, err := reconstructor.Open(sharesSummed)
				Expect(err).ToNot(HaveOccurred())
				Expect(recon.Eq(&secretSummed)).To(BeTrue())

				Expect(SharesAreConsistent(sharesSummed, &reconstructor, kmax)).To(BeTrue())
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
				sharer := NewSharer(indices)
				reconstructor := NewReconstructor(indices)

				for i := 0; i < trials; i++ {
					k = RandRange(1, n)
					secret = secp256k1.RandomFn()
					scale = secp256k1.RandomFn()
					secretScaled.Mul(&secret, &scale)

					_ = sharer.Share(&shares, secret, k)

					// Construct the summed shares
					for i := range sharesScaled {
						sharesScaled[i].Scale(&shares[i], &scale)
					}

					recon, err := reconstructor.Open(sharesScaled)
					Expect(err).ToNot(HaveOccurred())
					Expect(recon.Eq(&secretScaled)).To(BeTrue())

					Expect(SharesAreConsistent(sharesScaled, &reconstructor, k)).To(BeTrue())
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

		Specify("adding should add the values and leave the index unchanged", func() {
			var index, value1, value2, val, ind, sum secp256k1.Fn

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
				val = shareSum.Value()
				ind = shareSum.Index()
				Expect(val.Eq(&sum)).To(BeTrue())
				Expect(ind.Eq(&index)).To(BeTrue())

				// Adding two shares with different indices should panic.
				share1 = NewShare(secp256k1.RandomFn(), value1)
				Expect(func() { shareSum.Add(&share1, &share2) }).To(Panic())
			}
		})

		Specify("scaling should multiply the value and leave the index unchanged", func() {
			var scale, value, index, val, ind, prod secp256k1.Fn

			for i := 0; i < trials; i++ {
				index = secp256k1.RandomFn()
				value = secp256k1.RandomFn()
				scale = secp256k1.RandomFn()
				prod.Mul(&value, &scale)

				// The resulting share should have the value scaled and the
				// same index.
				share = NewShare(index, value)
				shareScale.Scale(&share, &scale)
				val = shareScale.Value()
				ind = shareScale.Index()
				Expect(val.Eq(&prod)).To(BeTrue())
				Expect(ind.Eq(&index)).To(BeTrue())
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
	// Sharer tests
	//
	// We will test the two failure branches of creating shares:
	//
	//	1. If k is larger than the number of indices, the function will return
	//	an error.
	//	2. If the destination slice is too small to hold all of the shares, the
	//	function will panic.
	//

	Context("Sharer", func() {
		trials := 100
		const n int = 20

		var indices []secp256k1.Fn
		var sharer Sharer

		BeforeEach(func() {
			indices = RandomIndices(n)
			sharer = NewSharer(indices)
		})

		It("should return an error when k is larger than the number of indices (1)", func() {
			maxK := 100
			shares := make(Shares, n)

			for i := 0; i < trials; i++ {
				k := RandRange(n+1, maxK)
				secret := secp256k1.RandomFn()
				err := sharer.Share(&shares, secret, k)

				Expect(err).To(HaveOccurred())
			}
		})

		It("should panic if the destination slice capacity is too small (2)", func() {
			for i := 0; i < trials; i++ {
				k := RandRange(1, n)
				secret := secp256k1.RandomFn()
				shares := make(Shares, rand.Intn(n))
				Expect(func() { sharer.Share(&shares, secret, k) }).Should(Panic())
			}
		})

		//
		// Miscellaneous Tests
		//

		It("should correctly report the number of indices", func() {
			Expect(sharer.N()).To(Equal(n))
		})

		//
		// Marshaling
		//

		var bs [4 + n*secp256k1.FnSizeMarshalled]byte

		It("should function correctly after marshalling and unmarshalling", func() {
			trials = 10
			var k int
			var secret secp256k1.Fn

			shares := make(Shares, n)
			sharer := NewSharer(indices)
			reconstructor := NewReconstructor(indices)

			for i := 0; i < trials; i++ {
				k = RandRange(1, n)
				secret = secp256k1.RandomFn()

				// Marhsal and unmarshal the sharer.
				bs, err := surge.ToBinary(&sharer)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(&sharer, bs[:])
				Expect(err).ToNot(HaveOccurred())

				err = sharer.Share(&shares, secret, k)
				Expect(err).ToNot(HaveOccurred())

				recon, err := reconstructor.Open(shares)
				Expect(err).ToNot(HaveOccurred())
				Expect(recon.Eq(&secret)).To(BeTrue())

				Expect(SharesAreConsistent(shares, &reconstructor, k)).To(BeTrue())
			}
		})

		It("should be able to unmarshal into an empty struct", func() {
			sharer = NewSharer(indices)
			sharer2 := Sharer{}

			_, _, _ = sharer.Marshal(bs[:], sharer.SizeHint())
			_, m, err := sharer2.Unmarshal(bs[:], sharer.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
		})
	})

	//
	// Reconstructor tests
	//
	// We will test the four failure modes for reconstructing:
	//
	//	1. It should return an error when there are too many shares.
	//	2. It should return and error when a share has an index that is not in
	//	the index set.
	//	3. It should return an error when two shares have the same index.
	//	4. When doing a checked reconstruction, it should return an error if
	//	the number of shares given is less than the specified k.
	//

	Context("Reconstructor", func() {
		trials := 100
		const n int = 20

		var indices []secp256k1.Fn
		var reconstructor Reconstructor
		var k int
		var secret secp256k1.Fn
		var bs [4 + n*secp256k1.FnSizeMarshalled]byte

		BeforeEach(func() {
			indices = RandomIndices(n)
			reconstructor = NewReconstructor(indices)
		})

		It("should return an error when the number of shares is too high (1)", func() {
			maxNumShares := 100
			shares := make(Shares, maxNumShares)

			for i := 0; i < trials; i++ {
				numShares := RandRange(n+1, maxNumShares)
				shares = shares[:numShares]
				_, err := reconstructor.Open(shares)

				Expect(err).To(HaveOccurred())
			}
		})

		var shares Shares
		initShares := func() {
			shares = make(Shares, n)
			for i := range shares {
				shares[i] = NewShare(indices[i], secp256k1.Fn{})
			}
		}

		It("should return an error when there is a share with an out of range index (2)", func() {
			initShares()

			for i := 0; i < trials; i++ {
				// Change one of the indices. It is possible that the random
				// index is actually valid, but the chance of this happening is
				// negligible
				shares[rand.Intn(n)] = NewShare(secp256k1.RandomFn(), secp256k1.Fn{})
				secret, err := reconstructor.Open(shares)

				Expect(err).To(HaveOccurred())
				Expect(secret.IsZero()).To(BeTrue())
			}
		})

		It("should return an error when two shares have the same index (3)", func() {
			initShares()

			for i := 0; i < trials; i++ {
				AddDuplicateIndex(shares)
				secret, err := reconstructor.Open(shares)

				Expect(err).To(HaveOccurred())
				Expect(secret.IsZero()).To(BeTrue())
			}
		})

		It("checked open give an error if there are not enough shares, and no error otherwise (4)", func() {
			var k, lowK, highK int

			initShares()

			for i := 0; i < trials; i++ {
				k = RandRange(1, n)
				lowK = rand.Intn(k)
				highK = RandRange(k, n)

				_, err := reconstructor.CheckedOpen(shares[:lowK], k)
				Expect(err).To(HaveOccurred())

				_, err = reconstructor.CheckedOpen(shares[:highK], k)
				Expect(err).ToNot(HaveOccurred())
			}
		})

		//
		// Miscellaneous Tests
		//

		It("should correctly report the number of indices", func() {
			Expect(reconstructor.N()).To(Equal(n))
		})

		//
		// Marshaling
		//

		It("should function correctly after marshalling and unmarshalling", func() {
			trials = 10
			shares := make(Shares, n)
			sharer := NewSharer(indices)

			for i := 0; i < trials; i++ {
				k = RandRange(1, n)
				secret = secp256k1.RandomFn()

				err := sharer.Share(&shares, secret, k)
				Expect(err).ToNot(HaveOccurred())

				// Marhsal and unmarshal the reconstructor.
				bs, err := surge.ToBinary(&reconstructor)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(&reconstructor, bs[:])
				Expect(err).ToNot(HaveOccurred())

				recon, err := reconstructor.Open(shares)
				Expect(err).ToNot(HaveOccurred())
				Expect(recon.Eq(&secret)).To(BeTrue())

				Expect(SharesAreConsistent(shares, &reconstructor, k)).To(BeTrue())
			}
		})

		It("should be able to unmarshal into an empty struct", func() {
			reconstructor = NewReconstructor(indices)
			reconstructor2 := Reconstructor{}

			_, _, _ = reconstructor.Marshal(bs[:], reconstructor.SizeHint())
			_, m, err := reconstructor2.Unmarshal(bs[:], reconstructor.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
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
	sharer := NewSharer(indices)
	secret := secp256k1.RandomFn()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sharer.Share(&shares, secret, k)
	}
}

func BenchmarkOpen(b *testing.B) {
	n := 100
	k := 33

	indices := RandomIndices(n)
	shares := make(Shares, n)
	sharer := NewSharer(indices)
	reconstructor := NewReconstructor(indices)
	secret := secp256k1.RandomFn()
	_ = sharer.Share(&shares, secret, k)
	Shuffle(shares)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = reconstructor.Open(shares[:k])
	}
}
