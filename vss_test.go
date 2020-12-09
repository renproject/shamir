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
//	4. Homomorphic under addition of a constant: Pedersen VSS is also
//	homomorphic under addition by some public constant value. We require a
//	property analogous to point 3 in this case.
//
//	5. Homomorphic under scaling: Pedersen VSS is also homomorphic under
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

	Context("Correctness (1)", func() {
		trials := 20
		n := 20

		var k int
		var secret secp256k1.Fn

		indices := RandomIndices(n)
		vshares := make(VerifiableShares, n)
		c := NewCommitmentWithCapacity(n)

		Specify("all shares constructed from the VSS scheme should be valid", func() {
			for i := 0; i < trials; i++ {
				// Create a random sharing.
				k = RandRange(1, n)
				secret = secp256k1.RandomFn()
				err := VShareSecret(&vshares, &c, indices, h, secret, k)
				Expect(err).ToNot(HaveOccurred())

				// Check that all shares are valid.
				for _, share := range vshares {
					Expect(IsValid(h, &c, &share)).To(BeTrue())
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
		var secret secp256k1.Fn

		BeforeEach(func() {
			indices = RandomIndices(n)
			vshares = make(VerifiableShares, n)
			c = NewCommitmentWithCapacity(n)
		})

		ShareAndCheckWithPerturbed := func(kLower int, perturbShare func(vs *VerifiableShare)) {
			for i := 0; i < trials; i++ {
				k = RandRange(kLower, n)
				secret = secp256k1.RandomFn()
				err := VShareSecret(&vshares, &c, indices, h, secret, k)
				Expect(err).ToNot(HaveOccurred())

				// Change one of the shares to be invalid
				badInd = rand.Intn(n)
				perturbShare(&vshares[badInd])

				for i, share := range vshares {
					Expect(IsValid(h, &c, &share)).To(Equal(i != badInd))
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
		var secret1, secret2, secretSummed secp256k1.Fn

		BeforeEach(func() {
			indices = RandomIndices(n)
			vshares1 = make(VerifiableShares, n)
			vshares2 = make(VerifiableShares, n)
			vsharesSummed = make(VerifiableShares, n)
			c1 = NewCommitmentWithCapacity(n)
			c2 = NewCommitmentWithCapacity(n)
			cSummed = NewCommitmentWithCapacity(n)
		})

		CreateShares := func(kLower int) {
			k1 = RandRange(kLower, n)
			k2 = RandRange(kLower, n)
			kmax = Max(k1, k2)
			secret1 = secp256k1.RandomFn()
			secret2 = secp256k1.RandomFn()
			secretSummed.Add(&secret1, &secret2)
			_ = VShareSecret(&vshares1, &c1, indices, h, secret1, k1)
			_ = VShareSecret(&vshares2, &c2, indices, h, secret2, k2)

			// Create the shares for the sum
			cSummed.Add(c1, c2)
			for i := range vsharesSummed {
				vsharesSummed[i].Add(&vshares1[i], &vshares2[i])
			}
		}

		PerturbAndCheck := func(perturb func(vs *VerifiableShare)) {
			badInd := rand.Intn(n)
			perturb(&vsharesSummed[badInd])

			// The shares should be valid
			for i, share := range vsharesSummed {
				Expect(IsValid(h, &cSummed, &share)).To(Equal(i != badInd))
			}
		}

		Specify("the summed shares should be valid (1)", func() {
			for i := 0; i < trials; i++ {
				CreateShares(1)

				// The shares should be valid
				for _, share := range vsharesSummed {
					Expect(IsValid(h, &cSummed, &share)).To(BeTrue())
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
			for i := 0; i < trials; i++ {
				CreateShares(1)

				sharesSummed := vsharesSummed.Shares()
				recon := Open(sharesSummed)
				Expect(recon.Eq(&secretSummed)).To(BeTrue())

				Expect(VsharesAreConsistent(vsharesSummed, kmax)).To(BeTrue())
			}
		})
	})

	// Tests for the Homomorphic addition of a constant property (4). This
	// property states that if we have a sharing and then add a public constant
	// (also adding the constant to the auxiliary information), we should get a
	// new sharing that is valid and corresponds to the sum of the original
	// secret and the constant. Specifically, we want the following to hold
	// after adding a constant to a sharing:
	//
	//	1. Each resulting share should be valid when checked against the new
	//	resulting auxiliary information.
	//	2. If one of the newly created shares is altered in any way, this share
	//	should fail the validity check of the new auxiliary information.
	//	3. The resulting shares should form a consistent sharing of the secret
	//	that is defined as the sum of the original secret and the constant.
	Context("Homomorphic addition of constant (4)", func() {
		trials := 20
		n := 20

		var k int
		var indices []secp256k1.Fn
		var vshares, vsharesSummed VerifiableShares
		var c, cSummed Commitment
		var secret, constant, secretSummed secp256k1.Fn

		BeforeEach(func() {
			indices = RandomIndices(n)
			vshares = make(VerifiableShares, n)
			vsharesSummed = make(VerifiableShares, n)
			c = NewCommitmentWithCapacity(n)
			cSummed = NewCommitmentWithCapacity(n)
		})

		CreateShares := func(kLower int) {
			k = RandRange(kLower, n)
			secret = secp256k1.RandomFn()
			constant = secp256k1.RandomFn()
			secretSummed.Add(&secret, &constant)
			_ = VShareSecret(&vshares, &c, indices, h, secret, k)

			// Create the shares for the sum
			cSummed.AddConstant(c, &constant)
			for i := range vsharesSummed {
				vsharesSummed[i].AddConstant(&vshares[i], &constant)
			}
		}

		PerturbAndCheck := func(perturb func(vs *VerifiableShare)) {
			badInd := rand.Intn(n)
			perturb(&vsharesSummed[badInd])

			// The shares should be valid
			for i, share := range vsharesSummed {
				Expect(IsValid(h, &cSummed, &share)).To(Equal(i != badInd))
			}
		}

		Specify("the summed shares should be valid (1)", func() {
			for i := 0; i < trials; i++ {
				CreateShares(1)

				// The shares should be valid
				for _, share := range vsharesSummed {
					Expect(IsValid(h, &cSummed, &share)).To(BeTrue())
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

		Specify("the resulting secret should be the sum of the original secret and the constant (3)", func() {
			for i := 0; i < trials; i++ {
				CreateShares(1)

				sharesSummed := vsharesSummed.Shares()
				recon := Open(sharesSummed)
				Expect(recon.Eq(&secretSummed)).To(BeTrue())

				Expect(VsharesAreConsistent(vsharesSummed, k)).To(BeTrue())
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
	Context("Homomorphic scaling (5)", func() {
		trials := 20
		n := 20

		var k int
		var indices []secp256k1.Fn
		var vshares, vsharesScaled VerifiableShares
		var c, cScaled Commitment
		var secret, scale, secretScaled secp256k1.Fn

		BeforeEach(func() {
			indices = RandomIndices(n)
			vshares = make(VerifiableShares, n)
			vsharesScaled = make(VerifiableShares, n)
			c = NewCommitmentWithCapacity(n)
			cScaled = NewCommitmentWithCapacity(n)
		})

		CreateShares := func(kLower int) {
			k = RandRange(kLower, n)
			secret = secp256k1.RandomFn()
			scale = secp256k1.RandomFn()
			secretScaled.Mul(&secret, &scale)
			_ = VShareSecret(&vshares, &c, indices, h, secret, k)

			// Create the scaled shares
			cScaled.Scale(c, &scale)
			for i := range vsharesScaled {
				vsharesScaled[i].Scale(&vshares[i], &scale)
			}
		}

		PerturbAndCheck := func(perturb func(vs *VerifiableShare)) {
			badInd := rand.Intn(n)
			perturb(&vsharesScaled[badInd])

			// The shares should be valid
			for i, share := range vsharesScaled {
				Expect(IsValid(h, &cScaled, &share)).To(Equal(i != badInd))
			}
		}

		Specify("the scaled shares should be valid (1)", func() {
			for i := 0; i < trials; i++ {
				CreateShares(1)

				// The shares should be valid
				for _, share := range vsharesScaled {
					Expect(IsValid(h, &cScaled, &share)).To(BeTrue())
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
			for i := 0; i < trials; i++ {
				CreateShares(1)

				sharesScaled := vsharesScaled.Shares()
				recon := Open(sharesScaled)
				Expect(recon.Eq(&secretScaled)).To(BeTrue())

				Expect(VsharesAreConsistent(vsharesScaled, k)).To(BeTrue())
			}
		})
	})

	//
	// Miscellaneous tests
	//

	Specify("trying to share when k is larger than n should fail", func() {
		n := 20

		indices := RandomIndices(n)

		err := VShareSecret(nil, nil, indices, h, secp256k1.Fn{}, n+1)
		Expect(err).To(HaveOccurred())
	})

	Context("Commitments", func() {
		trials := 100
		maxK := 10

		Specify("should be unequal when they have different lengths", func() {
			for i := 0; i < trials; i++ {
				k1 := rand.Intn(maxK) + 1
				k2 := k1
				for k2 == k1 {
					k2 = rand.Intn(maxK) + 1
				}
				com1 := RandomCommitment(k1)
				com2 := RandomCommitment(k2)

				Expect(com1.Eq(com2)).To(BeFalse())
			}
		})

		Specify("should be unequal when they have different curve points", func() {
			for i := 0; i < trials; i++ {
				k := rand.Intn(maxK) + 1
				com1 := RandomCommitment(k)
				com2 := RandomCommitment(k)

				Expect(com1.Eq(com2)).To(BeFalse())
			}
		})

		Specify("setting a commitment should make it equal to the argument", func() {
			var com2 Commitment
			for i := 0; i < trials; i++ {
				k := rand.Intn(maxK) + 1
				com1 := RandomCommitment(k)
				com2.Set(com1)

				Expect(com1.Eq(com2)).To(BeTrue())
			}
		})

		Specify("accessing and appending elements should work correctly", func() {
			points := make([]secp256k1.Point, maxK)

			for i := 0; i < trials; i++ {
				k := rand.Intn(maxK) + 1
				com := NewCommitmentWithCapacity(k)
				for j := 0; j < k; j++ {
					points[j] = secp256k1.RandomPoint()
					com.Append(points[j])
				}

				for j := 0; j < k; j++ {
					p := com[j]
					Expect(p.Eq(&points[j])).To(BeTrue())
				}
			}
		})

		It("should return the correct number of curve points", func() {
			for i := 0; i < trials; i++ {
				k := rand.Intn(maxK) + 1
				com := RandomCommitment(k)
				Expect(com.Len()).To(Equal(k))
			}
		})
	})

	Context("Verifiable shares", func() {
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
	})

	//
	// VerifiableShares tests
	//

	Context("VerifiableShares", func() {
		const maxN = 20
		const maxLen = 4 + maxN*VShareSize
		var bs [maxLen]byte

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

		It("should be able to unmarshal into an empty struct", func() {
			shares1 = shares1[:maxN]
			RandomiseVerifiableShares(shares1)
			shares2 = VerifiableShares{}

			_, _, _ = shares1.Marshal(bs[:], shares1.SizeHint())
			_, m, err := shares2.Unmarshal(bs[:], shares1.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))
			Expect(VerifiableSharesAreEq(shares1, shares2)).To(BeTrue())
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
	secret := secp256k1.RandomFn()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VShareSecret(&vshares, &c, indices, h, secret, k)
	}
}

func BenchmarkVSSVerify(b *testing.B) {
	n := 100
	k := 33
	h := secp256k1.RandomPoint()

	indices := RandomIndices(n)
	vshares := make(VerifiableShares, n)
	c := NewCommitmentWithCapacity(n)
	secret := secp256k1.RandomFn()
	_ = VShareSecret(&vshares, &c, indices, h, secret, k)
	ind := rand.Intn(n)
	share := vshares[ind]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValid(h, &c, &share)
	}
}
