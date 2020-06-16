package shamir_test

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir/curve"
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
	h := curve.Random()

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
		var secret secp256k1.Secp256k1N

		indices := RandomIndices(n)
		vshares := make(VerifiableShares, n)
		c := NewCommitmentWithCapacity(n)
		vssharer := NewVSSharer(indices, h)
		checker := NewVSSChecker(h)

		Specify("all shares constructed from the VSS scheme should be valid", func() {
			for i := 0; i < trials; i++ {
				// Create a random sharing.
				k = RandRange(1, n)
				secret = secp256k1.RandomSecp256k1N()
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
		var indices []secp256k1.Secp256k1N
		var vshares VerifiableShares
		var c Commitment
		var vssharer VSSharer
		var checker VSSChecker
		var secret secp256k1.Secp256k1N

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
				secret = secp256k1.RandomSecp256k1N()
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
		var indices []secp256k1.Secp256k1N
		var vshares1, vshares2, vsharesSummed VerifiableShares
		var c1, c2, cSummed Commitment
		var vssharer VSSharer
		var checker VSSChecker
		var secret1, secret2, secretSummed secp256k1.Secp256k1N

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
			secret1 = secp256k1.RandomSecp256k1N()
			secret2 = secp256k1.RandomSecp256k1N()
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
		var indices []secp256k1.Secp256k1N
		var vshares, vsharesScaled VerifiableShares
		var c, cScaled Commitment
		var vssharer VSSharer
		var checker VSSChecker
		var secret, scale, secretScaled secp256k1.Secp256k1N

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
			secret = secp256k1.RandomSecp256k1N()
			scale = secp256k1.RandomSecp256k1N()
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

		err := vsharer.Share(nil, nil, secp256k1.Secp256k1N{}, n+1)
		Expect(err).To(HaveOccurred())
	})

	Context("Commitments", func() {
		const maxK int = 10

		var trials int
		var com, com1, com2 Commitment
		var bs [curve.PointSizeBytes*maxK + 4]byte

		BeforeEach(func() {
			trials = 100
			com = NewCommitmentWithCapacity(maxK)
			com1 = NewCommitmentWithCapacity(maxK)
			com2 = NewCommitmentWithCapacity(maxK)
		})

		RandomCommitmentBytes := func(dst []byte, k int) {
			var point curve.Point
			binary.BigEndian.PutUint32(dst[:4], uint32(k))
			for i := 0; i < k; i++ {
				point = curve.Random()
				point.GetBytes(dst[4+i*curve.PointSizeBytes:])
			}
		}

		var RandomiseCommitment func(*Commitment, int)
		{
			var tmpBs [curve.PointSizeBytes*maxK + 4]byte
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
			points := make([]curve.Point, maxK)

			for i := 0; i < trials; i++ {
				k := rand.Intn(maxK) + 1
				com := NewCommitmentWithCapacity(k)
				for j := 0; j < k; j++ {
					points[j] = curve.Random()
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
					nBytes := curve.PointSizeBytes*com1.Len() + 4
					com1.GetBytes(bs[:nBytes])
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
					surge.FromBinary(bs, &com2)
					Expect(com1.Eq(&com2)).To(BeTrue())
				}
			})

			It("should be able to unmarshal into an empty struct", func() {
				buf := bytes.NewBuffer(bs[:])
				buf.Reset()
				RandomiseCommitment(&com1, maxK)
				com2 := Commitment{}

				_, _ = com1.Marshal(buf, com1.SizeHint())
				m, err := com2.Unmarshal(buf, com1.SizeHint())
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))
				Expect(com1.Eq(&com2)).To(BeTrue())
			})

			It("should error if marshalling fails", func() {
				k := rand.Intn(maxK) + 1
				RandomiseCommitment(&com, k)
				buf := bytes.NewBuffer(bs[:])

				for i := 0; i < trials; i++ {
					//
					// Error marshalling slice length.
					//

					// Writer not big enough.
					max := rand.Intn(4)
					w := NewBoundedWriter(max)
					rem, err := com.Marshal(&w, com.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(com.SizeHint() - max))

					// Max not big enough.
					max = rand.Intn(4)
					rem, err = com.Marshal(buf, max)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(max))

					//
					// Error marshalling a curve point.
					//

					// Writer not big enough.
					max = RandRange(4, com.SizeHint()-1)
					w = NewBoundedWriter(max)
					rem, err = com.Marshal(&w, com.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(com.SizeHint() - max))

					// Max not big enough.
					max = RandRange(4, com.SizeHint()-1)
					rem, err = com.Marshal(buf, max)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal((max - 4) % curve.PointSizeBytes))
				}
			})

			It("should error if unmarshalling with not enough remaining bytes for the slice len", func() {
				com := Commitment{}
				size := com.SizeHint()
				buf := bytes.NewBuffer(bs[:])

				for i := 0; i < trials; i++ {
					max := rand.Intn(size)
					m, err := com.Unmarshal(buf, max)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(max))
				}
			})

			It("should error if unmarshalling with not enough remaining bytes for the curve points", func() {
				for i := 0; i < trials; i++ {
					k := rand.Intn(maxK) + 1
					readCap := RandRange(4, curve.PointSizeBytes*k+4-1)
					dataLen := curve.PointSizeBytes*k + 4
					RandomCommitmentBytes(bs[:], k)
					buf := bytes.NewBuffer(bs[:dataLen])
					m, err := com.Unmarshal(buf, readCap)
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
					buf := bytes.NewBuffer(bs[:max])
					rem, err := com.Unmarshal(buf, com.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(com.SizeHint() - max))

					// Error unmarshalling a curve point.
					max = RandRange(4, com.SizeHint()-1)
					binary.BigEndian.PutUint32(bs[:4], uint32(k))
					buf = bytes.NewBuffer(bs[:max])
					size := k*curve.PointSizeBytes + 4
					rem, err = com.Unmarshal(buf, size)
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
						randomInvalidCurvePoint(bs[4+j*curve.PointSizeBytes:])
					}

					buf := bytes.NewBuffer(bs[:])
					m, err := com.Unmarshal(buf, curve.PointSizeBytes*maxK+4)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal((maxK - 1) * curve.PointSizeBytes))
				}
			})
		})
	})

	Context("Verifiable shares", func() {
		trials := 1000
		It("should be the same after marshalling to and from binary", func() {
			var share1, share2 VerifiableShare
			var bs [VShareSizeBytes]byte

			for i := 0; i < trials; i++ {
				share1 = NewVerifiableShare(
					NewShare(secp256k1.RandomSecp256k1N(), secp256k1.RandomSecp256k1N()),
					secp256k1.RandomSecp256k1N(),
				)
				share1.GetBytes(bs[:])
				share2.SetBytes(bs[:])
				Expect(share1.Eq(&share2)).To(BeTrue())
			}
		})

		It("should be the same after marshalling and unmarshalling with surge", func() {
			var share1, share2 VerifiableShare

			for i := 0; i < trials; i++ {
				share1 = NewVerifiableShare(
					NewShare(secp256k1.RandomSecp256k1N(), secp256k1.RandomSecp256k1N()),
					secp256k1.RandomSecp256k1N(),
				)
				bs, err := surge.ToBinary(&share1)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(bs[:], &share2)
				Expect(share1.Eq(&share2)).To(BeTrue())
			}
		})

		It("should be able to unmarshal into an empty struct", func() {
			var bs [VShareSizeBytes]byte
			buf := bytes.NewBuffer(bs[:])
			buf.Reset()
			share1 := NewVerifiableShare(
				NewShare(secp256k1.RandomSecp256k1N(), secp256k1.RandomSecp256k1N()),
				secp256k1.RandomSecp256k1N(),
			)
			share2 := VerifiableShare{}

			_, _ = share1.Marshal(buf, share1.SizeHint())
			m, err := share2.Unmarshal(buf, share1.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
			Expect(share1.Eq(&share2)).To(BeTrue())
		})

		It("should error if marshalling with remaining bytes less than required for the share", func() {
			var bs [VShareSizeBytes]byte
			share := VerifiableShare{}
			buf := bytes.NewBuffer(bs[:])

			for i := 0; i < trials; i++ {
				max := rand.Intn(ShareSizeBytes)
				m, err := share.Marshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(max % FnSizeBytes))
			}
		})

		It("should error if marshalling with remaining bytes less than required for the decommitment", func() {
			var bs [VShareSizeBytes]byte
			share := VerifiableShare{}
			buf := bytes.NewBuffer(bs[:])

			for i := 0; i < trials; i++ {
				max := RandRange(ShareSizeBytes, ShareSizeBytes+FnSizeBytes-1)
				m, err := share.Marshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(max - ShareSizeBytes))
			}
		})

		It("should error if unmarshalling with remaining bytes less than required", func() {
			var bs [VShareSizeBytes]byte
			share := VerifiableShare{}
			size := share.SizeHint()
			buf := bytes.NewBuffer(bs[:])

			for i := 0; i < trials; i++ {
				max := rand.Intn(size)
				m, err := share.Unmarshal(buf, max)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(max))
			}
		})

		It("should error if unmarshalling without enough data", func() {
			var bs [VShareSizeBytes]byte
			share := VerifiableShare{}
			size := share.SizeHint()
			readCap := size

			for i := 0; i < trials; i++ {
				dataLen := rand.Intn(size)
				buf := bytes.NewBuffer(bs[:dataLen])
				n, err := share.Unmarshal(buf, readCap)
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
		const maxLen = 4 + maxN*VShareSizeBytes
		var bs [maxLen]byte

		shares := make(VerifiableShares, maxN)
		shares1 := make(VerifiableShares, maxN)
		shares2 := make(VerifiableShares, maxN)
		buf := bytes.NewBuffer(bs[:])

		RandomiseVerifiableShares := func(shares VerifiableShares) {
			for i := range shares {
				shares[i] = NewVerifiableShare(
					NewShare(
						secp256k1.RandomSecp256k1N(),
						secp256k1.RandomSecp256k1N(),
					),
					secp256k1.RandomSecp256k1N(),
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
				buf.Reset()
				n := RandRange(0, maxN)
				shares1 = shares1[:n]
				RandomiseVerifiableShares(shares1)

				m, err := shares1.Marshal(buf, 4+n*VShareSizeBytes)
				Expect(err).ToNot(HaveOccurred())
				Expect(m).To(Equal(0))

				m, err = shares2.Unmarshal(buf, 4+n*VShareSizeBytes)
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
				err = surge.FromBinary(bs[:], &shares2)
				Expect(VerifiableSharesAreEq(shares1, shares2)).To(BeTrue())
			}
		})

		It("should be able to unmarshal into an empty struct", func() {
			buf.Reset()
			shares1 = shares1[:maxN]
			RandomiseVerifiableShares(shares1)
			shares2 := VerifiableShares{}

			_, _ = shares1.Marshal(buf, shares1.SizeHint())
			m, err := shares2.Unmarshal(buf, shares1.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
			Expect(VerifiableSharesAreEq(shares1, shares2)).To(BeTrue())
		})

		Context("Marshalling errors", func() {
			It("should return an error when the max is too small for the slice length", func() {
				for i := 0; i < trials; i++ {
					max := rand.Intn(4)
					m, err := shares.Marshal(buf, max)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(max))
				}
			})

			It("should return an error when the writer is too small for the slice length", func() {
				for i := 0; i < trials; i++ {
					max := rand.Intn(4)
					w := NewBoundedWriter(max)
					m, err := shares.Marshal(&w, 4)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(4 - max))
				}
			})

			It("should return an error when the max is too small for all of the shares", func() {
				for i := 0; i < trials; i++ {
					buf.Reset()
					n := RandRange(1, maxN)
					shares = shares[:n]
					RandomiseVerifiableShares(shares)
					max := RandRange(4, 4+n*VShareSizeBytes-1)

					m, err := shares.Marshal(buf, max)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal((max - 4) % FnSizeBytes))
				}
			})
		})

		Context("Unmarshalling errors", func() {
			It("should return an error when the max is too small for the slice length", func() {
				for i := 0; i < trials; i++ {
					buf.Reset()
					max := rand.Intn(4)

					m, err := shares2.Unmarshal(buf, max)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(max))
				}
			})

			It("should return an error when the reader is too small for the slice length", func() {
				for i := 0; i < trials; i++ {
					buf.Reset()
					max := rand.Intn(4)
					buf := bytes.NewBuffer(bs[:max])

					m, err := shares2.Unmarshal(buf, 4)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(4 - max))
				}
			})

			It("should return an error when the max is too small for all of the shares", func() {
				shares1 = shares1[:maxN]
				RandomiseVerifiableShares(shares1)

				for i := 0; i < trials; i++ {
					buf.Reset()
					shares1.Marshal(buf, maxLen)
					n := RandRange(1, maxN)
					max := RandRange(4, 4+n*VShareSizeBytes-1)

					m, err := shares2.Unmarshal(buf, max)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(max - 4))
				}
			})

			It("should return an error when the reader is too small for all of the shares", func() {
				binary.BigEndian.PutUint32(bs[:4], maxN)

				for i := 0; i < trials; i++ {
					n := RandRange(1, maxN)
					max := RandRange(4, 4+n*VShareSizeBytes-1)
					buf := bytes.NewBuffer(bs[:max])

					m, err := shares2.Unmarshal(buf, maxLen)
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
			var h curve.Point

			for i := 0; i < trials; i++ {
				h = curve.Random()
				checker = NewVSSChecker(h)
				bs, err := surge.ToBinary(&checker)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(bs[:], &checker)
				Expect(err).ToNot(HaveOccurred())
			}
		})

		It("should be able to unmarshal into an empty struct", func() {
			var bs [curve.PointSizeBytes]byte
			buf := bytes.NewBuffer(bs[:])
			buf.Reset()
			checker1 := NewVSSChecker(h)
			checker2 := VSSChecker{}

			_, _ = checker1.Marshal(buf, checker1.SizeHint())
			m, err := checker2.Unmarshal(buf, checker1.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
		})

		Specify("unmarhsalling should return an error if the data isn't valid", func() {
			var bs [curve.PointSizeBytes]byte

			for i := 0; i < trials; i++ {
				randomInvalidCurvePoint(bs[:])

				buf := bytes.NewBuffer(bs[:])
				m, err := checker.Unmarshal(buf, curve.PointSizeBytes)
				Expect(err).To(HaveOccurred())
				Expect(m).To(Equal(0))
			}
		})
	})

	Context("VSS Sharer", func() {
		trials := 20
		const n int = 20

		var k int
		var secret secp256k1.Secp256k1N
		var bs [4 + n*FnSizeBytes + curve.PointSizeBytes]byte

		indices := RandomIndices(n)
		vshares := make(VerifiableShares, n)
		c := NewCommitmentWithCapacity(n)
		vssharer := NewVSSharer(indices, h)
		checker := NewVSSChecker(h)

		It("should work correctly after marshalling and unmarshalling", func() {
			for i := 0; i < trials; i++ {
				// Create a random sharing.
				k = RandRange(1, n)
				secret = secp256k1.RandomSecp256k1N()

				// Marhsal and unmarshal the vssharer.
				bs, err := surge.ToBinary(&vssharer)
				Expect(err).ToNot(HaveOccurred())
				err = surge.FromBinary(bs[:], &vssharer)
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
			buf := bytes.NewBuffer(bs[:])
			buf.Reset()
			vssharer1 := NewVSSharer(indices, h)
			vssharer2 := VSSharer{}

			_, _ = vssharer1.Marshal(buf, vssharer1.SizeHint())
			m, err := vssharer2.Unmarshal(buf, vssharer1.SizeHint())
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
					w := NewBoundedWriter(max)
					rem, err := vssharer.Marshal(&w, vssharer.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(vssharer.SizeHint() - max))

					// Can't write all indices.
					max = RandRange(4, vssharer.SizeHint()-h.SizeHint()-1)
					w = NewBoundedWriter(max)
					rem, err = vssharer.Marshal(&w, vssharer.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(vssharer.SizeHint() - max))

					//
					// Error marshalling h.
					//
					max = RandRange(vssharer.SizeHint()-h.SizeHint(), vssharer.SizeHint()-1)
					w = NewBoundedWriter(max)
					rem, err = vssharer.Marshal(&w, vssharer.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(vssharer.SizeHint() - max))
				}
			})

			It("should fail if the max is not big enough", func() {
				vssharer = NewVSSharer(indices, h)
				buf := bytes.NewBuffer(bs[:])

				for i := 0; i < trials; i++ {
					//
					// Error marshalling the sharer.
					//

					// Can't write slice length.
					max := rand.Intn(4)
					rem, err := vssharer.Marshal(buf, max)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(max))

					// Can't write all indices.
					max = RandRange(4, vssharer.SizeHint()-h.SizeHint()-1)
					rem, err = vssharer.Marshal(buf, max)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal((max - 4) % FnSizeBytes))

					//
					// Error marshalling h.
					//
					max = RandRange(vssharer.SizeHint()-h.SizeHint(), vssharer.SizeHint()-1)
					rem, err = vssharer.Marshal(buf, max)
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
				buf := bytes.NewBuffer(bs[:])

				for i := 0; i < trials; i++ {
					max := rand.Intn(4)
					m, err := vssharer.Unmarshal(buf, max)
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
					m, err := vssharer.Unmarshal(buf, readCap)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(readCap - 4))
				}
			})

			It("should error if unmarshalling with not enough remaining bytes for h", func() {
				for i := 0; i < trials; i++ {
					readCap := RandRange(4+FnSizeBytes*n, 4+FnSizeBytes*n+h.SizeHint()-1)
					dataLen := 4 + FnSizeBytes*n + h.SizeHint()
					RandomSliceBytes(bs[:], n, FnSizeBytes, FillRandSecp)
					buf := bytes.NewBuffer(bs[:dataLen])
					m, err := vssharer.Unmarshal(buf, readCap)
					Expect(err).To(HaveOccurred())
					Expect(m).To(Equal(readCap - 4 - FnSizeBytes*n))
				}
			})

			It("should error if unmarshalling without enough data", func() {
				for i := 0; i < trials; i++ {
					k := rand.Intn(n) + 1
					indices = RandomIndices(k)
					vssharer = NewVSSharer(indices, h)

					// Error unmarshalling slice length.
					max := rand.Intn(4)
					buf := bytes.NewBuffer(bs[:max])
					rem, err := vssharer.Unmarshal(buf, vssharer.SizeHint())
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(vssharer.SizeHint() - max))

					// Error unmarshalling an index.
					max = RandRange(4, vssharer.SizeHint()-h.SizeHint()-1)
					binary.BigEndian.PutUint32(bs[:4], uint32(k))
					buf = bytes.NewBuffer(bs[:max])
					size := k*FnSizeBytes + 4
					rem, err = vssharer.Unmarshal(buf, size)
					Expect(err).To(HaveOccurred())
					Expect(rem).To(Equal(size - max))
				}
			})
		})
	})

	Context("Constants", func() {
		Specify("VShareSizeBytes should have the correct value", func() {
			vshare := VerifiableShare{}
			Expect(VShareSizeBytes).To(Equal(vshare.SizeHint()))
		})
	})
})

func BenchmarkVSShare(b *testing.B) {
	n := 100
	k := 33
	h := curve.Random()

	indices := RandomIndices(n)
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
	h := curve.Random()

	indices := RandomIndices(n)
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
