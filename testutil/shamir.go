package testutil

import (
	"math/rand"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
)

// RandomIndices initialises and returns a slice of n indices, each of which is
// random. Often it is desired that each index is distinct. This function does
// not gaurantee this, however the chance of two indices being equal is
// negligible for low n.
func RandomIndices(n int) []secp256k1.Secp256k1N {
	indices := make([]secp256k1.Secp256k1N, n)
	for i := range indices {
		indices[i] = secp256k1.RandomSecp256k1N()
	}
	return indices
}

// SequentialIndices initialises and returns a slice of n indices, where the
// slice index i is equal to i+1 in the field.
func SequentialIndices(n int) []secp256k1.Secp256k1N {
	indices := make([]secp256k1.Secp256k1N, n)
	one := secp256k1.OneSecp256k1N()
	for i := range indices {
		indices[i].Set(&one)
		indices[i].MulInt(i + 1)
	}

	return indices
}

// Shuffle randomises the order of the givens shares in the slice.
func Shuffle(shares shamir.Shares) {
	rand.Shuffle(len(shares), func(i, j int) {
		shares[i], shares[j] = shares[j], shares[i]
	})
}

// AddDuplicateIndex picks two random (distinct) indices in the given slice of
// shares and sets the share index of the second to be equal to that of the
// first.
func AddDuplicateIndex(shares shamir.Shares) {
	// Pick two distinct array indices.
	first, second := rand.Intn(len(shares)), rand.Intn(len(shares))
	for first == second {
		second = rand.Intn(len(shares))
	}

	// Set the second share to have the same index as the first.
	shares[second] = shamir.NewShare(shares[first].Index(), shares[second].Value())
}

// SharesAreConsistent returns true if the given shares are found to be
// consistent with the given secret after `trials` trials. Consistency is
// checked as follows. For each trial, a random subset of size at least k is
// picked, and then this subset is used to reconstruct a value. If the
// reconstruction returns an error, or if the value is not equal to the secret,
// an error is returned. Otherwise, the function will return true.
//
// NOTE: This function modifies the order of the shares in the given slice.
func SharesAreConsistent(shares shamir.Shares, reconstructor *shamir.Reconstructor, k int) bool {
	if len(shares) < k {
		return true
	}

	secret, err := reconstructor.Open(shares[:k])
	if err != nil {
		return false
	}
	for i := 1; i <= len(shares)-k; i++ {
		recon, err := reconstructor.Open(shares[i : i+k])
		if err != nil || !recon.Eq(&secret) {
			return false
		}
	}

	return true
}

// PerturbIndex modifies the given verifiable share to have a random index.
func PerturbIndex(vs *shamir.VerifiableShare) {
	share := vs.Share()
	*vs = shamir.NewVerifiableShare(
		shamir.NewShare(
			secp256k1.RandomSecp256k1N(), // Altered
			share.Value(),
		),
		vs.Decommitment(),
	)
}

// PerturbValue modifies the given verifiable share to have a random value.
func PerturbValue(vs *shamir.VerifiableShare) {
	share := vs.Share()
	*vs = shamir.NewVerifiableShare(
		shamir.NewShare(
			share.Index(),
			secp256k1.RandomSecp256k1N(), // Altered
		),
		vs.Decommitment(),
	)
}

// PerturbDecommitment modifies the given verifiable share to have a random
// decommitment value.
func PerturbDecommitment(vs *shamir.VerifiableShare) {
	*vs = shamir.NewVerifiableShare(
		vs.Share(),
		secp256k1.RandomSecp256k1N(), // Altered
	)
}

// VsharesAreConsistent is a wrapper around SharesAreConsistent for the
// VerifiableShares type.
func VsharesAreConsistent(vshares shamir.VerifiableShares, reconstructor *shamir.Reconstructor, k int) bool {
	return SharesAreConsistent(vshares.Shares(), reconstructor, k)
}
