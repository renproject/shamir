package shamirutil

import (
	"math/rand"

	"github.com/renproject/secp256k1"
	shamirsecp256k1 "github.com/renproject/shamir/secp256k1"
)

// RandomCommitment constructs and returns a random commitment with the given
// number of curve points.
func RandomCommitment(k int) shamirsecp256k1.Commitment {
	c := make(shamirsecp256k1.Commitment, k)
	for i := range c {
		c[i] = secp256k1.RandomPoint()
	}
	return c
}

// RandomIndices initialises and returns a slice of n indices, each of which is
// random. Often it is desired that each index is distinct. This function does
// not gaurantee this, however the chance of two indices being equal is
// negligible for low n.
func RandomIndices(n int) []secp256k1.Fn {
	indices := make([]secp256k1.Fn, n)
	for i := range indices {
		indices[i] = secp256k1.RandomFn()
	}
	return indices
}

// SequentialIndices initialises and returns a slice of n indices, where the
// slice index i is equal to i+1 in the field.
func SequentialIndices(n int) []secp256k1.Fn {
	indices := make([]secp256k1.Fn, n)
	for i := range indices {
		indices[i].SetU16(uint16(i) + 1)
	}

	return indices
}

// Shuffle randomises the order of the givens shares in the slice.
func Shuffle(shares shamirsecp256k1.Shares) {
	rand.Shuffle(len(shares), func(i, j int) {
		shares[i], shares[j] = shares[j], shares[i]
	})
}

// AddDuplicateIndex picks two random (distinct) indices in the given slice of
// shares and sets the share index of the second to be equal to that of the
// first.
func AddDuplicateIndex(shares shamirsecp256k1.Shares) {
	// Pick two distinct array indices.
	first, second := rand.Intn(len(shares)), rand.Intn(len(shares))
	for first == second {
		second = rand.Intn(len(shares))
	}

	// Set the second share to have the same index as the first.
	shares[second].Index = shares[first].Index
}

// SharesAreConsistent returns true if the given shares are found to be
// consistent. Consistency is defined as all points lying on some polynomial of
// degree less than `k`.
func SharesAreConsistent(shares shamirsecp256k1.Shares, k int) bool {
	if len(shares) < k {
		return true
	}

	secret := shamirsecp256k1.Open(shares[:k])
	for i := 1; i <= len(shares)-k; i++ {
		recon := shamirsecp256k1.Open(shares[i : i+k])
		if !recon.Eq(&secret) {
			return false
		}
	}

	return true
}

// PerturbIndex modifies the given verifiable share to have a random index.
func PerturbIndex(vs *shamirsecp256k1.VerifiableShare) {
	vs.Share.Index = secp256k1.RandomFn()
}

// PerturbValue modifies the given verifiable share to have a random value.
func PerturbValue(vs *shamirsecp256k1.VerifiableShare) {
	vs.Share.Value = secp256k1.RandomFn()
}

// PerturbDecommitment modifies the given verifiable share to have a random
// decommitment value.
func PerturbDecommitment(vs *shamirsecp256k1.VerifiableShare) {
	vs.Decommitment = secp256k1.RandomFn()
}

// VsharesAreConsistent is a wrapper around SharesAreConsistent for the
// VerifiableShares type.
func VsharesAreConsistent(
	vshares shamirsecp256k1.VerifiableShares,
	k int,
) bool {
	return SharesAreConsistent(vshares.Shares(), k)
}
