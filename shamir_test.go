package shamir_test

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/surge"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir"
	. "github.com/renproject/shamir/testutil"
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

	zero := secp256k1.ZeroSecp256k1N()

	Context("Sharing consistency (1)", func() {
		trials := 100
		n := 20

		var k int
		var secret secp256k1.Secp256k1N

		Specify("any qualified subset can reconstruct the secret correctly", func() {
			indices := RandomIndices(n)
			shares := make(Shares, n)
			sharer := NewSharer(indices)
			reconstructor := NewReconstructor(indices)

			for i := 0; i < trials; i++ {
				k = RandRange(1, n)
				secret = secp256k1.RandomSecp256k1N()

				err := sharer.Share(&shares, secret, k)
				Expect(err).ToNot(HaveOccurred())

				Expect(
					SharesAreConsistent(shares, secret, &reconstructor, k, 100),
				).To(BeTrue())
			}
		})
	})

	Context("Homomorphic under addition (2)", func() {
		trials := 100
		n := 20

		var k1, k2, kmax int
		var secret1, secret2, secretSummed secp256k1.Secp256k1N

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
				secret1 = secp256k1.RandomSecp256k1N()
				secret2 = secp256k1.RandomSecp256k1N()
				secretSummed.Add(&secret1, &secret2)

				_ = sharer.Share(&shares1, secret1, k1)
				_ = sharer.Share(&shares2, secret2, k2)

				// Construct the summed shares
				for i := range sharesSummed {
					sharesSummed[i].Add(&shares1[i], &shares2[i])
				}

				Expect(
					SharesAreConsistent(sharesSummed, secretSummed, &reconstructor, kmax, 100),
				).To(BeTrue())
			}
		})
	})

	Context("Homomorphic under scaling (3)", func() {
		trials := 100
		n := 20

		var k int
		var secret, scale, secretScaled secp256k1.Secp256k1N

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
					secret = secp256k1.RandomSecp256k1N()
					scale = secp256k1.RandomSecp256k1N()
					secretScaled.Mul(&secret, &scale)

					_ = sharer.Share(&shares, secret, k)

					// Construct the summed shares
					for i := range sharesScaled {
						sharesScaled[i].Scale(&shares[i], &scale)
					}

					Expect(
						SharesAreConsistent(sharesScaled, secretScaled, &reconstructor, k, 100),
					).To(BeTrue())
				}
			},
		)
	})

	//
	// Share tests
	//

	Context("Shares", func() {
		trials := 100

		var bs [ShareSizeBytes]byte
		var share, share1, share2, shareSum, shareScale Share

		Specify("adding should add the values and leave the index unchanged", func() {
			var index, value1, value2, val, ind, sum secp256k1.Secp256k1N

			for i := 0; i < trials; i++ {
				index = secp256k1.RandomSecp256k1N()
				value1 = secp256k1.RandomSecp256k1N()
				value2 = secp256k1.RandomSecp256k1N()
				sum.Add(&value1, &value2)
				sum.Normalize()

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
				share1 = NewShare(secp256k1.RandomSecp256k1N(), value1)
				Expect(func() { shareSum.Add(&share1, &share2) }).To(Panic())
			}
		})

		Specify("scaling should multiply the value and leave the index unchanged", func() {
			var scale, value, index, val, ind, prod secp256k1.Secp256k1N

			for i := 0; i < trials; i++ {
				index = secp256k1.RandomSecp256k1N()
				value = secp256k1.RandomSecp256k1N()
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

		It("should be the same after marshalling to and from binary", func() {
			for i := 0; i < trials; i++ {
				share1 = NewShare(secp256k1.RandomSecp256k1N(), secp256k1.RandomSecp256k1N())
				share1.GetBytes(bs[:])
				share2.SetBytes(bs[:])
				Expect(share1.Eq(&share2)).To(BeTrue())
			}
		})

		It("should be the same after marshalling and unmarshalling with surge", func() {
			for i := 0; i < trials; i++ {
				share1 = NewShare(secp256k1.RandomSecp256k1N(), secp256k1.RandomSecp256k1N())
				bs, err := surge.ToBinary(&share1)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(bs[:], &share2)
				Expect(share1.Eq(&share2)).To(BeTrue())
			}
		})

		It("should error if marshalling with remaining bytes less than 64", func() {
			for i := 0; i < trials; i++ {
				share := NewShare(secp256k1.RandomSecp256k1N(), secp256k1.RandomSecp256k1N())
				max := rand.Intn(ShareSizeBytes)
				buf := bytes.NewBuffer(bs[:])
				n, err := share.Marshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(n).To(Equal(max))
			}
		})

		It("should error if unmarshalling fails", func() {
			for i := 0; i < trials; i++ {
				share := NewShare(secp256k1.RandomSecp256k1N(), secp256k1.RandomSecp256k1N())
				max := rand.Intn(ShareSizeBytes)
				buf := bytes.NewBuffer(bs[:max])
				n, err := share.Unmarshal(buf, ShareSizeBytes)
				Expect(err).To(HaveOccurred())
				Expect(n).To(Equal(ShareSizeBytes - max))
			}
		})

		It("should error if unmarshalling with remaining bytes less than 64", func() {
			for i := 0; i < trials; i++ {
				share := NewShare(secp256k1.RandomSecp256k1N(), secp256k1.RandomSecp256k1N())
				max := rand.Intn(ShareSizeBytes)
				buf := bytes.NewBuffer(bs[:])
				n, err := share.Unmarshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(n).To(Equal(max))
			}
		})
	})

	//
	// Shares tests
	//

	Context("Shares", func() {
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

		var indices []secp256k1.Secp256k1N
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
				secret := secp256k1.RandomSecp256k1N()
				err := sharer.Share(&shares, secret, k)

				Expect(err).To(HaveOccurred())
			}
		})

		It("should panic if the destination slice capacity is too small (2)", func() {
			for i := 0; i < trials; i++ {
				k := RandRange(1, n)
				secret := secp256k1.RandomSecp256k1N()
				shares := make(Shares, rand.Intn(n))
				Expect(func() { sharer.Share(&shares, secret, k) }).Should(Panic())
			}
		})

		//
		// Marshaling
		//

		var bs [4 + n*FnSizeBytes]byte

		It("should function correctly after marshalling and unmarshalling", func() {
			trials = 10
			var k int
			var secret secp256k1.Secp256k1N

			shares := make(Shares, n)
			sharer := NewSharer(indices)
			reconstructor := NewReconstructor(indices)

			for i := 0; i < trials; i++ {
				k = RandRange(1, n)
				secret = secp256k1.RandomSecp256k1N()

				// Marhsal and unmarshal the sharer.
				bs, err := surge.ToBinary(&sharer)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(bs[:], &sharer)
				Expect(err).ToNot(HaveOccurred())

				err = sharer.Share(&shares, secret, k)
				Expect(err).ToNot(HaveOccurred())

				Expect(
					SharesAreConsistent(shares, secret, &reconstructor, k, 100),
				).To(BeTrue())
			}
		})

		It("should error if marshalling fails", func() {
			sharer = NewSharer(indices)
			buf := bytes.NewBuffer(bs[:])

			for i := 0; i < trials; i++ {
				//
				// Error marshalling slice length.
				//

				// Writer not big enough.
				max := rand.Intn(4)
				w := NewBoundedWriter(max)
				rem, err := sharer.Marshal(&w, sharer.SizeHint())
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal(sharer.SizeHint() - max))

				// Max not big enough.
				max = rand.Intn(4)
				rem, err = sharer.Marshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal(max))

				//
				// Error marshalling an index.
				//

				// Writer not big enough.
				max = RandRange(4, sharer.SizeHint()-1)
				w = NewBoundedWriter(max)
				rem, err = sharer.Marshal(&w, sharer.SizeHint())
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal(sharer.SizeHint() - max))

				// Max not big enough.
				max = RandRange(4, sharer.SizeHint()-1)
				rem, err = sharer.Marshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal((max - 4) % FnSizeBytes))
			}
		})

		It("should error if unmarshalling with not enough remaining bytes for the slice len", func() {
			sharer = Sharer{}
			size := sharer.SizeHint()
			buf := bytes.NewBuffer(bs[:])

			for i := 0; i < trials; i++ {
				max := rand.Intn(size)
				m, err := sharer.Unmarshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(max))
			}
		})

		It("should error if unmarshalling with not enough remaining bytes for the indices", func() {
			for i := 0; i < trials; i++ {
				k := rand.Intn(n) + 1
				readCap := RandRange(4, FnSizeBytes*k+4-1)
				dataLen := FnSizeBytes*k + 4
				RandomSliceBytes(bs[:], k, FnSizeBytes, FillRandSecp)
				buf := bytes.NewBuffer(bs[:dataLen])
				m, err := sharer.Unmarshal(buf, readCap)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(readCap - 4))
			}
		})

		It("should error if unmarshalling without enough data", func() {
			for i := 0; i < trials; i++ {
				k := rand.Intn(n) + 1
				indices = RandomIndices(k)
				sharer = NewSharer(indices)

				// Error unmarshalling slice length.
				max := rand.Intn(4)
				buf := bytes.NewBuffer(bs[:max])
				rem, err := sharer.Unmarshal(buf, sharer.SizeHint())
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal(sharer.SizeHint() - max))

				// Error unmarshalling an index.
				max = RandRange(4, sharer.SizeHint()-1)
				binary.BigEndian.PutUint32(bs[:4], uint32(k))
				buf = bytes.NewBuffer(bs[:max])
				size := k*FnSizeBytes + 4
				rem, err = sharer.Unmarshal(buf, size)
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal(size - max))
			}
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

		var indices []secp256k1.Secp256k1N
		var reconstructor Reconstructor
		var k int
		var secret secp256k1.Secp256k1N
		var bs [4 + n*FnSizeBytes]byte

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
				shares[i] = NewShare(indices[i], zero)
			}
		}

		It("should return an error when there is a share with an out of range index (2)", func() {
			initShares()

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
		// Marshaling
		//

		It("should function correctly after marshalling and unmarshalling", func() {
			trials = 10
			shares := make(Shares, n)
			sharer := NewSharer(indices)

			for i := 0; i < trials; i++ {
				k = RandRange(1, n)
				secret = secp256k1.RandomSecp256k1N()

				err := sharer.Share(&shares, secret, k)
				Expect(err).ToNot(HaveOccurred())

				// Marhsal and unmarshal the reconstructor.
				bs, err := surge.ToBinary(&reconstructor)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(bs[:], &reconstructor)
				Expect(err).ToNot(HaveOccurred())

				Expect(
					SharesAreConsistent(shares, secret, &reconstructor, k, 100),
				).To(BeTrue())
			}
		})

		It("should error if marshalling fails", func() {
			reconstructor = NewReconstructor(indices)
			buf := bytes.NewBuffer(bs[:])

			for i := 0; i < trials; i++ {
				//
				// Error marshalling slice length.
				//

				// Writer not big enough.
				max := rand.Intn(4)
				w := NewBoundedWriter(max)
				rem, err := reconstructor.Marshal(&w, reconstructor.SizeHint())
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal(reconstructor.SizeHint() - max))

				// Max not big enough.
				max = rand.Intn(4)
				rem, err = reconstructor.Marshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal(max))

				//
				// Error marshalling an index.
				//

				// Writer not big enough.
				max = RandRange(4, reconstructor.SizeHint()-1)
				w = NewBoundedWriter(max)
				rem, err = reconstructor.Marshal(&w, reconstructor.SizeHint())
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal(reconstructor.SizeHint() - max))

				// Max not big enough.
				max = RandRange(4, reconstructor.SizeHint()-1)
				rem, err = reconstructor.Marshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal((max - 4) % FnSizeBytes))
			}
		})

		It("should error if unmarshalling with not enough remaining bytes for the slice len", func() {
			reconstructor = Reconstructor{}
			size := reconstructor.SizeHint()
			buf := bytes.NewBuffer(bs[:])

			for i := 0; i < trials; i++ {
				max := rand.Intn(size)
				m, err := reconstructor.Unmarshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(max))
			}
		})

		It("should error if unmarshalling with not enough remaining bytes for the indices", func() {
			for i := 0; i < trials; i++ {
				k := rand.Intn(n) + 1
				readCap := RandRange(4, FnSizeBytes*k+4-1)
				dataLen := FnSizeBytes*k + 4
				RandomSliceBytes(bs[:], k, FnSizeBytes, FillRandSecp)
				buf := bytes.NewBuffer(bs[:dataLen])
				m, err := reconstructor.Unmarshal(buf, readCap)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(readCap - 4))
			}
		})

		It("should error if unmarshalling without enough data", func() {
			for i := 0; i < trials; i++ {
				k := rand.Intn(n) + 1
				indices = RandomIndices(k)
				reconstructor = NewReconstructor(indices)

				// Error unmarshalling slice length.
				max := rand.Intn(4)
				buf := bytes.NewBuffer(bs[:max])
				rem, err := reconstructor.Unmarshal(buf, reconstructor.SizeHint())
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal(reconstructor.SizeHint() - max))

				// Error unmarshalling an index.
				max = RandRange(4, reconstructor.SizeHint()-1)
				binary.BigEndian.PutUint32(bs[:4], uint32(k))
				buf = bytes.NewBuffer(bs[:max])
				size := k*FnSizeBytes + 4
				rem, err = reconstructor.Unmarshal(buf, size)
				Expect(err).To(HaveOccurred())
				Expect(rem).To(Equal(size - max))
			}
		})
	})

	//
	// Miscellaneous Tests
	//

	Context("Constants", func() {
		Specify("FnSizeBytes should have correct value", func() {
			x := secp256k1.Secp256k1N{}
			Expect(FnSizeBytes).To(Equal(x.SizeHint()))
		})

		Specify("ShareSizeBytes should have correct value", func() {
			share := Share{}
			Expect(ShareSizeBytes).To(Equal(share.SizeHint()))
		})
	})
})

func BenchmarkShare(b *testing.B) {
	n := 100
	k := 33

	indices := RandomIndices(n)
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

	indices := RandomIndices(n)
	shares := make(Shares, n)
	sharer := NewSharer(indices)
	reconstructor := NewReconstructor(indices)
	secret := secp256k1.RandomSecp256k1N()
	_ = sharer.Share(&shares, secret, k)
	Shuffle(shares)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = reconstructor.Open(shares[:k])
	}
}
