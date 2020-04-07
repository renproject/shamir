package shamir_test

import (
	"math/rand"
	"testing"
	"time"

	. "github.com/renproject/shamir"
	"github.com/renproject/shamir/curve"
	. "github.com/renproject/shamir/testutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/renproject/secp256k1-go"
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
				Expect(
					VsharesAreConsistent(vsharesSummed, secretSummed, &reconstructor, kmax, 100),
				).To(BeTrue())
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
				Expect(
					VsharesAreConsistent(vsharesScaled, secretScaled, &reconstructor, k, 100),
				).To(BeTrue())
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
