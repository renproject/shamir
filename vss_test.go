package shamir_test

import (
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	"github.com/renproject/secp256k1"
	"github.com/renproject/surge"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir"
	. "github.com/renproject/shamir/testutil"
)

// The key properties of verifiable secret sharing is that it is the same as
// normal secret sharing, except that additional auxiliary information is
// included within and without the shares that allows other parties to verify
// that any shares they receive are correct. Thus to reduce overlap with
// testing for standard Shamir shares, we aim to test the properties that are
// unique to verifiable shares. These are as follows.
//
//	1. Correctness: The shares and commitments produced by the relevant
//	function calls should be correct. That is, all thusly created shares should
//	constitute a consistent sharing of some secret, and should be found to be
//	valid when checking their validity using the auxiliary information.
//
//	2. Soundness: Any shares that are altered after that have been correctly
//	constructed by the VSS scheme should be detectable. That is, when checking
//	the validity of such a share with the produced auxiliary information, the
//	check should fail.
//
//	3. Homomorphic under addition: Pedersen VSS is homomorphic under addition,
//	which means that if we have two verifiable shares and their respective
//	commitments from two different sharings of respective secrets, we can "add"
//	the shares and the commitments such that we end up with a new share and
//	commitment. Further, this new share and commitment will form part of a
//	valid verifiable sharing of the sum of the two original secrets.
//
//	4. Homomorphic under scaling: Pedersen VSS is also homomorphic under
//	scaling by some public constant value. We require a property analogous to
//	point 3 in this case.
//
var _ = Describe("Verifiable secret sharing", func() {
	rand.Seed(time.Now().UnixNano())

	// Pedersen commitment parameter. This curve point needs to be a generator
	// of the elliptic curve group. Since the group has prime order, any curve
	// point is a generator (expect for the identity), and so we may just one
	// at random. Note that in practice it is crucial that no one knows
	// log_g(h), that is, no one should know a number x such that h = g^x. For
	// testing this obivously does not matter.
	h := secp256k1.RandomPoint()

	randomInvalidCurvePoint := func(bs []byte) {
		// The data is just that of a curve point. The probability that a
		// random 64 bytes will represent a point on the curve is negligible.
		rand.Read(bs[:64])

		// Make sure that it does not represent the point at infinity.
		bs[64] = 0
	}

	Context("Correctness (1)", func() {
		trials := 20
		n := 20

		var k int
		var secret secp256k1.Fn

		indices := RandomIndices(n)
		vshares := make(VerifiableShares, n)
		c := NewCommitmentWithCapacity(n)
		vssharer := NewVSSharer(indices, h)
		checker := NewVSSChecker(h)

		Specify("all shares constructed from the VSS scheme should be valid", func() {
			for i := 0; i < trials; i++ {
				// Create a random sharing.
				k = RandRange(1, n)
				secret = secp256k1.RandomFn()
				err := vssharer.Share(&vshares, &c, secret, k)
				Expect(err).ToNot(HaveOccurred())

				// Check that all shares are valid.
				for _, share := range vshares {
					Expect(checker.IsValid(&c, &share)).To(BeTrue())
				}
			}
		})
	})

	// Tests for the soundness property (2). We want to check that any shares
	// that get altered are detected by the checker. There are three ways in
	// which a share can be altered:
	//
	//	1. The index of the share could be changed.
	//	2. The value of the share could be changed.
	//	3. The decommitment value of the verifiable share could be changed.
	Context("Soundness (2)", func() {
		trials := 20
		n := 20

		var k, badInd int
		var indices []secp256k1.Fn
		var vshares VerifiableShares
		var c Commitment
		var vssharer VSSharer
		var checker VSSChecker
		var secret secp256k1.Fn

		BeforeEach(func() {
			indices = RandomIndices(n)
			vshares = make(VerifiableShares, n)
			c = NewCommitmentWithCapacity(n)
			vssharer = NewVSSharer(indices, h)
			checker = NewVSSChecker(h)
		})

		ShareAndCheckWithPerturbed := func(kLower int, perturbShare func(vs *VerifiableShare)) {
			for i := 0; i < trials; i++ {
				k = RandRange(kLower, n)
				secret = secp256k1.RandomFn()
				err := vssharer.Share(&vshares, &c, secret, k)
				Expect(err).ToNot(HaveOccurred())

				// Change one of the shares to be invalid
				badInd = rand.Intn(n)
				perturbShare(&vshares[badInd])

				for i, share := range vshares {
					Expect(checker.IsValid(&c, &share)).To(Equal(i != badInd))
				}
			}
		}

		Specify("a share with a modified index should be invalid (1)", func() {
			// We need to ensure that k is at least 2, otherwise every point on
			// the sharing polynomial is the same and changing the index won't
			// actually make the share invalid.
			ShareAndCheckWithPerturbed(2, PerturbIndex)
		})

		Specify("a share with a modified value should be invalid (2)", func() {
			ShareAndCheckWithPerturbed(1, PerturbValue)
		})

		Specify("a share with a modified decommitment should be invalid (3)", func() {
			ShareAndCheckWithPerturbed(1, PerturbDecommitment)
		})
	})

	// Tests for the Homomorphic addition property (3). This property states
	// that if we have two sharings and then add them together (including the
	// auxiliary information), we should get a new sharing that is valid and
	// corresponds to the sum of the original two secrets. Specifically, we
	// want the following to hold after adding two verifiable sharings
	// together:
	//
	//	1. Each summed share should be valid when checked against the new
	//	"summed" auxiliary information.
	//	2. If one of the newly created shares is altered in any way, this share
	//	should fail the validity check of the new auxiliary information.
	//	3. The summed shares should form a consistent sharing of the secret
	//	that is defined as the sum of the two original secrets.
	Context("Homomorphic addition (3)", func() {
		trials := 20
		n := 20

		var k1, k2, kmax int
		var indices []secp256k1.Fn
		var vshares1, vshares2, vsharesSummed VerifiableShares
		var c1, c2, cSummed Commitment
		var vssharer VSSharer
		var checker VSSChecker
		var secret1, secret2, secretSummed secp256k1.Fn

		BeforeEach(func() {
			indices = RandomIndices(n)
			vshares1 = make(VerifiableShares, n)
			vshares2 = make(VerifiableShares, n)
			vsharesSummed = make(VerifiableShares, n)
			c1 = NewCommitmentWithCapacity(n)
			c2 = NewCommitmentWithCapacity(n)
			cSummed = NewCommitmentWithCapacity(n)
			vssharer = NewVSSharer(indices, h)
			checker = NewVSSChecker(h)
		})

		CreateShares := func(kLower int) {
			k1 = RandRange(kLower, n)
			k2 = RandRange(kLower, n)
			kmax = Max(k1, k2)
			secret1 = secp256k1.RandomFn()
			secret2 = secp256k1.RandomFn()
			secretSummed.Add(&secret1, &secret2)
			_ = vssharer.Share(&vshares1, &c1, secret1, k1)
			_ = vssharer.Share(&vshares2, &c2, secret2, k2)

			// Create the shares for the sum
			cSummed.Add(&c1, &c2)
			for i := range vsharesSummed {
				vsharesSummed[i].Add(&vshares1[i], &vshares2[i])
			}
		}

		PerturbAndCheck := func(perturb func(vs *VerifiableShare)) {
			badInd := rand.Intn(n)
			perturb(&vsharesSummed[badInd])

			// The shares should be valid
			for i, share := range vsharesSummed {
				Expect(checker.IsValid(&cSummed, &share)).To(Equal(i != badInd))
			}
		}

		Specify("the summed shares should be valid (1)", func() {
			for i := 0; i < trials; i++ {
				CreateShares(1)

				// The shares should be valid
				for _, share := range vsharesSummed {
					Expect(checker.IsValid(&cSummed, &share)).To(BeTrue())
				}
			}
		})

		// The parts of a share that can be maliciously altered are the:
		//	1. Index
		//	2. Value
		//	3. Decommitment
		Specify("a share with an altered index should be detected (2.1)", func() {
			for i := 0; i < trials; i++ {
				// We need to ensure that k is at least 2, otherwise every
				// point on the sharing polynomial is the same and changing the
				// index won't actually make the share invalid.
				CreateShares(2)
				PerturbAndCheck(PerturbIndex)
			}
		})

		Specify("a share with an altered value should be detected (2.2)", func() {
			for i := 0; i < trials; i++ {
				CreateShares(1)
				PerturbAndCheck(PerturbValue)
			}
		})

		Specify("a share with an altered decommitment should be detected (2.3)", func() {
			for i := 0; i < trials; i++ {
				CreateShares(1)
				PerturbAndCheck(PerturbDecommitment)
			}
		})

		Specify("the resulting secret should be the sum of the original secrets (3)", func() {
			reconstructor := NewReconstructor(indices)

			for i := 0; i < trials; i++ {
				CreateShares(1)

				sharesSummed := vsharesSummed.Shares()
				recon, err := reconstructor.Open(sharesSummed)
				Expect(err).ToNot(HaveOccurred())
				Expect(recon.Eq(&secretSummed)).To(BeTrue())

				Expect(VsharesAreConsistent(vsharesSummed, &reconstructor, kmax)).To(BeTrue())
			}
		})
	})

	// Tests for the Homomorphic scaling property (4). This property states
	// that if we have a sharing and then scale it by some scalar (including
	// the auxiliary information), we should get a new sharing that is valid
	// and corresponds to the product of the original two secret and the
	// scalar. Specifically, we want the following to hold after scaling a
	// verifiable sharing:
	//
	//	1. Each scaled share should be valid when checked against the new
	//	"scaled" auxiliary information.
	//	2. If one of the newly created shares is altered in any way, this share
	//	should fail the validity check of the new auxiliary information.
	//	3. The scaled shares should form a consistent sharing of the secret
	//	that is defined as the product of the original secret and the scalar.
	Context("Homomorphic scaling (4)", func() {
		trials := 20
		n := 20

		var k int
		var indices []secp256k1.Fn
		var vshares, vsharesScaled VerifiableShares
		var c, cScaled Commitment
		var vssharer VSSharer
		var checker VSSChecker
		var secret, scale, secretScaled secp256k1.Fn

		BeforeEach(func() {
			indices = RandomIndices(n)
			vshares = make(VerifiableShares, n)
			vsharesScaled = make(VerifiableShares, n)
			c = NewCommitmentWithCapacity(n)
			cScaled = NewCommitmentWithCapacity(n)
			vssharer = NewVSSharer(indices, h)
			checker = NewVSSChecker(h)
		})

		CreateShares := func(kLower int) {
			k = RandRange(kLower, n)
			secret = secp256k1.RandomFn()
			scale = secp256k1.RandomFn()
			secretScaled.Mul(&secret, &scale)
			_ = vssharer.Share(&vshares, &c, secret, k)

			// Create the scaled shares
			cScaled.Scale(&c, &scale)
			for i := range vsharesScaled {
				vsharesScaled[i].Scale(&vshares[i], &scale)
			}
		}

		PerturbAndCheck := func(perturb func(vs *VerifiableShare)) {
			badInd := rand.Intn(n)
			perturb(&vsharesScaled[badInd])

			// The shares should be valid
			for i, share := range vsharesScaled {
				Expect(checker.IsValid(&cScaled, &share)).To(Equal(i != badInd))
			}
		}

		Specify("the scaled shares should be valid (1)", func() {
			for i := 0; i < trials; i++ {
				CreateShares(1)

				// The shares should be valid
				for _, share := range vsharesScaled {
					Expect(checker.IsValid(&cScaled, &share)).To(BeTrue())
				}
			}
		})

		// The parts of a share that can be maliciously altered are the:
		//	1. Index
		//	2. Value
		//	3. Decommitment
		Specify("a share with an altered index should be detected (2.1)", func() {
			for i := 0; i < trials; i++ {
				// We need to ensure that k is at least 2, otherwise every
				// point on the sharing polynomial is the same and changing the
				// index won't actually make the share invalid.
				CreateShares(2)
				PerturbAndCheck(PerturbIndex)
			}
		})

		Specify("a share with an altered value should be detected (2.2)", func() {
			for i := 0; i < trials; i++ {
				CreateShares(1)
				PerturbAndCheck(PerturbValue)
			}
		})

		Specify("a share with an altered decommitment should be detected (2.3)", func() {
			for i := 0; i < trials; i++ {
				CreateShares(1)
				PerturbAndCheck(PerturbDecommitment)
			}
		})

		Specify("the resulting secret should be the product of the original secret and the scale (3)", func() {
			reconstructor := NewReconstructor(indices)

			for i := 0; i < trials; i++ {
				CreateShares(1)

				sharesScaled := vsharesScaled.Shares()
				recon, err := reconstructor.Open(sharesScaled)
				Expect(err).ToNot(HaveOccurred())
				Expect(recon.Eq(&secretScaled)).To(BeTrue())

				Expect(VsharesAreConsistent(vsharesScaled, &reconstructor, k)).To(BeTrue())
			}
		})
	})

	//
	// Miscellaneous tests
	//

	Specify("trying to share when k is larger than n should fail", func() {
		n := 20

		indices := RandomIndices(n)
		vsharer := NewVSSharer(indices, h)

		err := vsharer.Share(nil, nil, secp256k1.Fn{}, n+1)
		Expect(err).To(HaveOccurred())
	})

	Context("Commitments", func() {
		const maxK int = 10

		var trials int
		var com, com1, com2 Commitment
		var bs [secp256k1.PointSize*maxK + 4]byte

		BeforeEach(func() {
			trials = 100
			com = NewCommitmentWithCapacity(maxK)
			com1 = NewCommitmentWithCapacity(maxK)
			com2 = NewCommitmentWithCapacity(maxK)
		})

		RandomCommitmentBytes := func(dst []byte, k int) {
			var point secp256k1.Point
			binary.BigEndian.PutUint32(dst[:4], uint32(k))
			for i := 0; i < k; i++ {
				point = secp256k1.RandomPoint()
				point.PutBytes(dst[4+i*secp256k1.PointSize:])
			}
		}

		var RandomiseCommitment func(*Commitment, int)
		{
			var tmpBs [secp256k1.PointSize*maxK + 4]byte
			RandomiseCommitment = func(dst *Commitment, k int) {
				RandomCommitmentBytes(tmpBs[:], k)
				dst.SetBytes(tmpBs[:])
			}
		}

		Specify("should be equal when they are the same", func() {
			for i := 0; i < trials; i++ {
				k := rand.Intn(maxK) + 1
				RandomCommitmentBytes(bs[:], k)
				com1.SetBytes(bs[:])
				com2.SetBytes(bs[:])

				Expect(com1.Eq(&com2)).To(BeTrue())
			}
		})

		Specify("should be unequal when they have different lengths", func() {
			for i := 0; i < trials; i++ {
				k1 := rand.Intn(maxK) + 1
				k2 := k1
				for k2 == k1 {
					k2 = rand.Intn(maxK) + 1
				}
				RandomiseCommitment(&com1, k1)
				RandomiseCommitment(&com2, k2)

				Expect(com1.Eq(&com2)).To(BeFalse())
			}
		})

		Specify("should be unequal when they have different curve points", func() {
			for i := 0; i < trials; i++ {
				k := rand.Intn(maxK) + 1
				RandomiseCommitment(&com1, k)
				RandomiseCommitment(&com2, k)

				Expect(com1.Eq(&com2)).To(BeFalse())
			}
		})

		Specify("setting a commitment should make it equal to the argument", func() {
			for i := 0; i < trials; i++ {
				k := rand.Intn(maxK) + 1
				RandomiseCommitment(&com1, k)
				com2.Set(com1)

				Expect(com1.Eq(&com2)).To(BeTrue())
			}
		})

		Specify("accessing and appending elements should work correctly", func() {
			points := make([]secp256k1.Point, maxK)

			for i := 0; i < trials; i++ {
				k := rand.Intn(maxK) + 1
				com := NewCommitmentWithCapacity(k)
				for j := 0; j < k; j++ {
					points[j] = secp256k1.RandomPoint()
					com.AppendPoint(points[j])
				}

				for j := 0; j < k; j++ {
					p := com.GetPoint(j)
					Expect(p.Eq(&points[j])).To(BeTrue())
				}
			}
		})

		//
		// Marshalling
		//

		Context("Marhsalling", func() {
			Specify("marshalling a commitment to and from binary should leave it unchanged", func() {
				for i := 0; i < trials; i++ {
					k := rand.Intn(maxK) + 1
					RandomiseCommitment(&com1, k)
					nBytes := secp256k1.PointSize*com1.Len() + 4
					com1.PutBytes(bs[:nBytes])
					com2.SetBytes(bs[:nBytes])
					Expect(com1.Eq(&com2)).To(BeTrue())
				}
			})

			Specify("marshalling and unmarshalling a commitment using surge should leave it unchanged", func() {
				for i := 0; i < trials; i++ {
					k := rand.Intn(maxK) + 1
					RandomiseCommitment(&com1, k)
					bs, err := surge.ToBinary(&com1)
					Expect(err).ToNot(HaveOccurred())
					surge.FromBinary(&com2, bs)
					Expect(com1.Eq(&com2)).To(BeTrue())
				}
			})

			It("should be able to unmarshal into an empty struct", func() {
				RandomiseCommitment(&com1, maxK)
				com2 := Commitment{}

				_, _, _ = com1.Marshal(bs[:], com1.SizeHint())
				_, m, err := com2.Unmarshal(bs[:], com1.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))
				Expect(com1.Eq(&com2)).To(BeTrue())
			})

			It("should error if marshalling fails", func() {
				k := rand.Intn(maxK) + 1
				RandomiseCommitment(&com, k)

				for i := 0; i < trials; i++ {
					//
					// Error marshalling slice length.
					//

					// Writer not big enough.
					max := rand.Intn(4)
					_, rem, err := com.Marshal(bs[:], com.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(com.SizeHint() - max))

					// Max not big enough.
					max = rand.Intn(4)
					_, rem, err = com.Marshal(bs[:], max)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(max))

					//
					// Error marshalling a curve point.
					//

					// Writer not big enough.
					max = RandRange(4, com.SizeHint()-1)
					_, rem, err = com.Marshal(bs[:], com.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(com.SizeHint() - max))

					// Max not big enough.
					max = RandRange(4, com.SizeHint()-1)
					_, rem, err = com.Marshal(bs[:], max)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal((max - 4) % secp256k1.PointSize))
				}
			})

			It("should error if unmarshalling with not enough remaining bytes for the slice len", func() {
				com := Commitment{}
				size := com.SizeHint()

				for i := 0; i < trials; i++ {
					max := rand.Intn(size)
					_, m, err := com.Unmarshal(bs[:], max)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(max))
				}
			})

			It("should error if unmarshalling with not enough remaining bytes for the curve points", func() {
				for i := 0; i < trials; i++ {
					k := rand.Intn(maxK) + 1
					readCap := RandRange(4, secp256k1.PointSize*k+4-1)
					RandomCommitmentBytes(bs[:], k)
					_, m, err := com.Unmarshal(bs[:], readCap)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(readCap - 4))
				}
			})

			It("should error if unmarshalling without enough data", func() {
				for i := 0; i < trials; i++ {
					k := rand.Intn(maxK) + 1
					RandomiseCommitment(&com, k)

					// Error unmarshalling slice length.
					max := rand.Intn(4)
					_, rem, err := com.Unmarshal(bs[:], com.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(com.SizeHint() - max))

					// Error unmarshalling a curve point.
					max = RandRange(4, com.SizeHint()-1)
					binary.BigEndian.PutUint32(bs[:4], uint32(k))
					size := k*secp256k1.PointSize + 4
					_, rem, err = com.Unmarshal(bs[:], size)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(size - max))
				}
			})

			Specify("unmarhsalling should return an error if the data doesn't represent a curve point", func() {
				for i := 0; i < trials; i++ {
					// Make sure that the slice length data is valid so that it
					// can proceed to unmarshalling the curve points.
					binary.BigEndian.PutUint32(bs[:4], uint32(maxK))

					for j := 0; j < maxK; j++ {
						randomInvalidCurvePoint(bs[4+j*secp256k1.PointSize:])
					}

					_, m, err := com.Unmarshal(bs[:], secp256k1.PointSize*maxK+4)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal((maxK - 1) * secp256k1.PointSize))
				}
			})
		})
	})

	Context("Verifiable shares", func() {
		trials := 1000
		It("should be the same after marshalling to and from binary", func() {
			var share1, share2 VerifiableShare
			var bs [VShareSize]byte

			for i := 0; i < trials; i++ {
				share1 = NewVerifiableShare(
					NewShare(secp256k1.RandomFn(), secp256k1.RandomFn()),
					secp256k1.RandomFn(),
				)
				share1.PutBytes(bs[:])
				share2.SetBytes(bs[:])
				Expect(share1.Eq(&share2)).To(BeTrue())
			}
		})

		It("should be the same after marshalling and unmarshalling with surge", func() {
			var share1, share2 VerifiableShare

			for i := 0; i < trials; i++ {
				share1 = NewVerifiableShare(
					NewShare(secp256k1.RandomFn(), secp256k1.RandomFn()),
					secp256k1.RandomFn(),
				)
				bs, err := surge.ToBinary(&share1)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(&share2, bs[:])
				Expect(share1.Eq(&share2)).To(BeTrue())
			}
		})

		It("should be able to unmarshal into an empty struct", func() {
			var bs [VShareSize]byte
			share1 := NewVerifiableShare(
				NewShare(secp256k1.RandomFn(), secp256k1.RandomFn()),
				secp256k1.RandomFn(),
			)
			share2 := VerifiableShare{}

			_, _, _ = share1.Marshal(bs[:], share1.SizeHint())
			_, m, err := share2.Unmarshal(bs[:], share1.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
			Expect(share1.Eq(&share2)).To(BeTrue())
		})

		It("should error if marshalling with remaining bytes less than required for the share", func() {
			var bs [VShareSize]byte
			share := VerifiableShare{}

			for i := 0; i < trials; i++ {
				max := rand.Intn(ShareSize)
				_, m, err := share.Marshal(bs[:], max)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(max % secp256k1.FnSize))
			}
		})

		It("should error if marshalling with remaining bytes less than required for the decommitment", func() {
			var bs [VShareSize]byte
			share := VerifiableShare{}

			for i := 0; i < trials; i++ {
				max := RandRange(ShareSize, ShareSize+secp256k1.FnSize-1)
				_, m, err := share.Marshal(bs[:], max)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(max - ShareSize))
			}
		})

		It("should error if unmarshalling with remaining bytes less than required", func() {
			var bs [VShareSize]byte
			share := VerifiableShare{}
			size := share.SizeHint()

			for i := 0; i < trials; i++ {
				max := rand.Intn(size)
				_, m, err := share.Unmarshal(bs[:], max)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(max))
			}
		})

		It("should error if unmarshalling without enough data", func() {
			var bs [VShareSize]byte
			share := VerifiableShare{}
			size := share.SizeHint()
			readCap := size

			for i := 0; i < trials; i++ {
				dataLen := rand.Intn(size)
				_, n, err := share.Unmarshal(bs[:], readCap)
				Expect(err).To(HaveOccurred())
				Expect(n).To(Equal(readCap - dataLen))
			}
		})
	})

	//
	// VerifiableShares tests
	//

	Context("VerifiableShares", func() {
		trials := 1000
		const maxN = 20
		const maxLen = 4 + maxN*VShareSize
		var bs [maxLen]byte

		shares := make(VerifiableShares, maxN)
		shares1 := make(VerifiableShares, maxN)
		shares2 := make(VerifiableShares, maxN)

		RandomiseVerifiableShares := func(shares VerifiableShares) {
			for i := range shares {
				shares[i] = NewVerifiableShare(
					NewShare(
						secp256k1.RandomFn(),
						secp256k1.RandomFn(),
					),
					secp256k1.RandomFn(),
				)
			}
		}

		VerifiableSharesAreEq := func(shares1, shares2 VerifiableShares) bool {
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

		It("should be the same after marshalling and unmarshalling", func() {
			for i := 0; i < trials; i++ {
				n := RandRange(0, maxN)
				shares1 = shares1[:n]
				RandomiseVerifiableShares(shares1)

				_, m, err := shares1.Marshal(bs[:], 4+n*VShareSize)
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				_, m, err = shares2.Unmarshal(bs[:], 4+n*VShareSize)
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				Expect(VerifiableSharesAreEq(shares1, shares2)).To(BeTrue())
			}
		})

		It("should be the same after marshalling with surge", func() {
			for i := 0; i < trials; i++ {
				n := RandRange(0, maxN)
				shares1 = shares1[:n]
				RandomiseVerifiableShares(shares1)

				bs, err := surge.ToBinary(&shares1)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(&shares2, bs[:])
				Expect(VerifiableSharesAreEq(shares1, shares2)).To(BeTrue())
			}
		})

		It("should be able to unmarshal into an empty struct", func() {
			shares1 = shares1[:maxN]
			RandomiseVerifiableShares(shares1)
			shares2 := VerifiableShares{}

			_, _, _ = shares1.Marshal(bs[:], shares1.SizeHint())
			_, m, err := shares2.Unmarshal(bs[:], shares1.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
			Expect(VerifiableSharesAreEq(shares1, shares2)).To(BeTrue())
		})

		Context("Marshalling errors", func() {
			It("should return an error when the max is too small for the slice length", func() {
				for i := 0; i < trials; i++ {
					max := rand.Intn(4)
					_, m, err := shares.Marshal(bs[:], max)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(max))
				}
			})

			It("should return an error when the writer is too small for the slice length", func() {
				for i := 0; i < trials; i++ {
					max := rand.Intn(4)
					_, m, err := shares.Marshal(bs[:], 4)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(4 - max))
				}
			})

			It("should return an error when the max is too small for all of the shares", func() {
				for i := 0; i < trials; i++ {
					n := RandRange(1, maxN)
					shares = shares[:n]
					RandomiseVerifiableShares(shares)
					max := RandRange(4, 4+n*VShareSize-1)

					_, m, err := shares.Marshal(bs[:], max)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal((max - 4) % secp256k1.FnSize))
				}
			})
		})

		Context("Unmarshalling errors", func() {
			It("should return an error when the max is too small for the slice length", func() {
				for i := 0; i < trials; i++ {
					max := rand.Intn(4)

					_, m, err := shares2.Unmarshal(bs[:], max)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(max))
				}
			})

			It("should return an error when the reader is too small for the slice length", func() {
				for i := 0; i < trials; i++ {
					max := rand.Intn(4)

					_, m, err := shares2.Unmarshal(bs[:], 4)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(4 - max))
				}
			})

			It("should return an error when the max is too small for all of the shares", func() {
				shares1 = shares1[:maxN]
				RandomiseVerifiableShares(shares1)

				for i := 0; i < trials; i++ {
					n := RandRange(1, maxN)
					max := RandRange(4, 4+n*VShareSize-1)

					_, m, err := shares2.Unmarshal(bs[:], max)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(max - 4))
				}
			})

			It("should return an error when the reader is too small for all of the shares", func() {
				binary.BigEndian.PutUint32(bs[:4], maxN)

				for i := 0; i < trials; i++ {
					n := RandRange(1, maxN)
					max := RandRange(4, 4+n*VShareSize-1)

					_, m, err := shares2.Unmarshal(bs[:], maxLen)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(maxLen - max))
				}
			})
		})
	})

	Context("VSS Checker", func() {
		trials := 1000

		var checker VSSChecker

		It("should marshall and unmarshall with surge successfully", func() {
			var h secp256k1.Point

			for i := 0; i < trials; i++ {
				h = secp256k1.RandomPoint()
				checker = NewVSSChecker(h)
				bs, err := surge.ToBinary(&checker)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(&checker, bs[:])
				Expect(err).ToNot(HaveOccurred())
			}
		})

		It("should be able to unmarshal into an empty struct", func() {
			var bs [secp256k1.PointSize]byte
			checker1 := NewVSSChecker(h)
			checker2 := VSSChecker{}

			_, _, _ = checker1.Marshal(bs[:], checker1.SizeHint())
			_, m, err := checker2.Unmarshal(bs[:], checker1.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
		})

		Specify("unmarhsalling should return an error if the data isn't valid", func() {
			var bs [secp256k1.PointSize]byte

			for i := 0; i < trials; i++ {
				randomInvalidCurvePoint(bs[:])

				_, m, err := checker.Unmarshal(bs[:], secp256k1.PointSize)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(0))
			}
		})
	})

	Context("VSS Sharer", func() {
		trials := 20
		const n int = 20

		var k int
		var secret secp256k1.Fn
		var bs [4 + n*secp256k1.FnSize + secp256k1.PointSize]byte

		indices := RandomIndices(n)
		vshares := make(VerifiableShares, n)
		c := NewCommitmentWithCapacity(n)
		vssharer := NewVSSharer(indices, h)
		checker := NewVSSChecker(h)

		It("should work correctly after marshalling and unmarshalling", func() {
			for i := 0; i < trials; i++ {
				// Create a random sharing.
				k = RandRange(1, n)
				secret = secp256k1.RandomFn()

				// Marhsal and unmarshal the vssharer.
				bs, err := surge.ToBinary(&vssharer)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(&vssharer, bs[:])
				Expect(err).ToNot(HaveOccurred())

				err = vssharer.Share(&vshares, &c, secret, k)
				Expect(err).ToNot(HaveOccurred())

				// Check that all shares are valid.
				for _, share := range vshares {
					Expect(checker.IsValid(&c, &share)).To(BeTrue())
				}
			}
		})

		It("should be able to unmarshal into an empty struct", func() {
			vssharer1 := NewVSSharer(indices, h)
			vssharer2 := VSSharer{}

			_, _, _ = vssharer1.Marshal(bs[:], vssharer1.SizeHint())
			_, m, err := vssharer2.Unmarshal(bs[:], vssharer1.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
		})

		Context("Marhsalling errors", func() {
			It("should fail if the writer is not big enough", func() {
				vssharer = NewVSSharer(indices, h)

				for i := 0; i < trials; i++ {
					//
					// Error marshalling the sharer.
					//

					// Can't write slice length.
					max := rand.Intn(4)
					_, rem, err := vssharer.Marshal(bs[:], vssharer.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(vssharer.SizeHint() - max))

					// Can't write all indices.
					max = RandRange(4, vssharer.SizeHint()-h.SizeHint()-1)
					_, rem, err = vssharer.Marshal(bs[:], vssharer.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(vssharer.SizeHint() - max))

					//
					// Error marshalling h.
					//
					max = RandRange(vssharer.SizeHint()-h.SizeHint(), vssharer.SizeHint()-1)
					_, rem, err = vssharer.Marshal(bs[:], vssharer.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(vssharer.SizeHint() - max))
				}
			})

			It("should fail if the max is not big enough", func() {
				vssharer = NewVSSharer(indices, h)

				for i := 0; i < trials; i++ {
					//
					// Error marshalling the sharer.
					//

					// Can't write slice length.
					max := rand.Intn(4)
					_, rem, err := vssharer.Marshal(bs[:], max)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(max))

					// Can't write all indices.
					max = RandRange(4, vssharer.SizeHint()-h.SizeHint()-1)
					_, rem, err = vssharer.Marshal(bs[:], max)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal((max - 4) % secp256k1.FnSize))

					//
					// Error marshalling h.
					//
					max = RandRange(vssharer.SizeHint()-h.SizeHint(), vssharer.SizeHint()-1)
					_, rem, err = vssharer.Marshal(bs[:], max)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(max - vssharer.SizeHint() + h.SizeHint()))
				}
			})

			It("should correctly report the number of indices", func() {
				Expect(vssharer.N()).To(Equal(n))
			})
		})

		Context("Unmarshalling errors", func() {
			It("should error if unmarshalling with not enough remaining bytes for the slice len", func() {
				vssharer = VSSharer{}

				for i := 0; i < trials; i++ {
					max := rand.Intn(4)
					_, m, err := vssharer.Unmarshal(bs[:], max)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(max))
				}
			})

			It("should error if unmarshalling with not enough remaining bytes for the indices", func() {
				for i := 0; i < trials; i++ {
					k := rand.Intn(n) + 1
					readCap := RandRange(4, secp256k1.FnSize*k+4-1)
					RandomSliceBytes(bs[:], k, secp256k1.FnSize, FillRandSecp)
					_, m, err := vssharer.Unmarshal(bs[:], readCap)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(readCap - 4))
				}
			})

			It("should error if unmarshalling with not enough remaining bytes for h", func() {
				for i := 0; i < trials; i++ {
					readCap := RandRange(4+secp256k1.FnSize*n, 4+secp256k1.FnSize*n+h.SizeHint()-1)
					RandomSliceBytes(bs[:], n, secp256k1.FnSize, FillRandSecp)
					_, m, err := vssharer.Unmarshal(bs[:], readCap)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(readCap - 4 - secp256k1.FnSize*n))
				}
			})

			It("should error if unmarshalling without enough data", func() {
				for i := 0; i < trials; i++ {
					k := rand.Intn(n) + 1
					indices = RandomIndices(k)
					vssharer = NewVSSharer(indices, h)

					// Error unmarshalling slice length.
					max := rand.Intn(4)
					_, rem, err := vssharer.Unmarshal(bs[:], vssharer.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(vssharer.SizeHint() - max))

					// Error unmarshalling an index.
					max = RandRange(4, vssharer.SizeHint()-h.SizeHint()-1)
					binary.BigEndian.PutUint32(bs[:4], uint32(k))
					size := k*secp256k1.FnSize + 4
					_, rem, err = vssharer.Unmarshal(bs[:], size)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(size - max))
				}
			})
		})
	})

	Context("Constants", func() {
		Specify("VShareSize should have the correct value", func() {
			vshare := VerifiableShare{}
			Expect(VShareSize).To(Equal(vshare.SizeHint()))
		})
	})
})

func BenchmarkVSShare(b *testing.B) {
	n := 100
	k := 33
	h := secp256k1.RandomPoint()

	indices := RandomIndices(n)
	vshares := make(VerifiableShares, n)
	c := NewCommitmentWithCapacity(n)
	vssharer := NewVSSharer(indices, h)
	secret := secp256k1.RandomFn()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = vssharer.Share(&vshares, &c, secret, k)
	}
}

func BenchmarkVSSVerify(b *testing.B) {
	n := 100
	k := 33
	h := secp256k1.RandomPoint()

	indices := RandomIndices(n)
	vshares := make(VerifiableShares, n)
	c := NewCommitmentWithCapacity(n)
	vssharer := NewVSSharer(indices, h)
	checker := NewVSSChecker(h)
	secret := secp256k1.RandomFn()
	_ = vssharer.Share(&vshares, &c, secret, k)
	ind := rand.Intn(100)
	share := vshares[ind]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.IsValid(&c, &share)
	}
}
