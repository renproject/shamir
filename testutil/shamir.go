package testutil

import (
	"math/rand"

	"github.com/renproject/secp256k1-go"
	"github.com/renproject/shamir"
)

func RandomIndices(n int) []secp256k1.Secp256k1N {
	indices := make([]secp256k1.Secp256k1N, n)
	for i := range indices {
		indices[i] = secp256k1.RandomSecp256k1N()
	}
	return indices
}

func SequentialIndices(n int) []secp256k1.Secp256k1N {
	indices := make([]secp256k1.Secp256k1N, n)
	one := secp256k1.OneSecp256k1N()
	for i := range indices {
		indices[i].Set(&one)
		indices[i].MulInt(i + 1)
	}

	return indices
}

func Shuffle(shares shamir.Shares) {
	rand.Shuffle(len(shares), func(i, j int) {
		shares[i], shares[j] = shares[j], shares[i]
	})
}

func AddDuplicateIndex(shares shamir.Shares) {
	// Pick two distinct array indices.
	first, second := rand.Intn(len(shares)), rand.Intn(len(shares))
	for first == second {
		second = rand.Intn(len(shares))
	}

	// Set the second share to have the same index as the first.
	shares[second] = shamir.NewShare(shares[first].Index(), shares[second].Value())
}

func SharesAreConsistent(
	shares shamir.Shares,
	secret secp256k1.Secp256k1N,
	reconstructor *shamir.Reconstructor,
	k, trials int,
) bool {
	for i := 0; i < trials; i++ {
		Shuffle(shares)
		extra := RandRange(0, len(shares)-k)
		recon, err := reconstructor.Open(shares[:k+extra])
		if err != nil || !recon.Eq(&secret) {
			return false
		}
	}

	return true
}

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

func PerturbDecommitment(vs *shamir.VerifiableShare) {
	*vs = shamir.NewVerifiableShare(
		vs.Share(),
		secp256k1.RandomSecp256k1N(), // Altered
	)
}

func VsharesAreConsistent(
	vshares shamir.VerifiableShares,
	secret secp256k1.Secp256k1N,
	reconstructor *shamir.Reconstructor,
	k, trials int,
) bool {
	shares := make(shamir.Shares, len(vshares))

	for i, vshare := range vshares {
		shares[i] = vshare.Share()
	}

	return SharesAreConsistent(shares, secret, reconstructor, k, trials)
}
