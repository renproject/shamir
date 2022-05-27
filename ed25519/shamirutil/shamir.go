package shamirutil

import (
	"fmt"
	"github.com/renproject/shamir/ed25519"
	"github.com/renproject/surge"
	"math/rand"
	"reflect"
	"testing/quick"
	"time"
)

// RandomIndices initialises and returns a slice of n indices, each of which is
// random. Often it is desired that each index is distinct. This function does
// not gaurantee this, however the chance of two indices being equal is
// negligible for low n.
func RandomIndices(n int) []ed25519.Scalar {
	indices := make([]ed25519.Scalar, n)
	for i := range indices {
		indices[i] = ed25519.RandomScalar()
	}
	return indices
}

// SequentialIndices initialises and returns a slice of n indices, where the
// slice index i is equal to i+1 in the field.
func SequentialIndices(n int) []ed25519.Scalar {
	indices := make([]ed25519.Scalar, n)
	for i := range indices {
		indices[i].SetU32(uint32(i) + 1)
	}

	return indices
}

// Shuffle randomises the order of the givens shares in the slice.
func Shuffle(shares ed25519.Shares) {
	rand.Shuffle(len(shares), func(i, j int) {
		shares[i], shares[j] = shares[j], shares[i]
	})
}

// AddDuplicateIndex picks two random (distinct) indices in the given slice of
// shares and sets the share index of the second to be equal to that of the
// first.
func AddDuplicateIndex(shares ed25519.Shares) {
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
func SharesAreConsistent(shares ed25519.Shares, k int) bool {
	if len(shares) < k {
		return true
	}

	secret := ed25519.Open(shares[:k])
	for i := 1; i <= len(shares)-k; i++ {
		recon := ed25519.Open(shares[i : i+k])
		if !recon.Eq(&secret) {
			return false
		}
	}

	return true
}

// RandomCommitment constructs and returns a random commitment with the given
// number of curve points.
func RandomCommitment(k int) ed25519.Commitment {
	c := make(ed25519.Commitment, k)
	for i := range c {
		c[i] = ed25519.RandomPoint()
	}
	return c
}

// PerturbIndex modifies the given verifiable share to have a random index.
func PerturbIndex(vs *ed25519.VerifiableShare) {
	vs.Share.Index = ed25519.RandomScalar()
}

// PerturbValue modifies the given verifiable share to have a random value.
func PerturbValue(vs *ed25519.VerifiableShare) {
	vs.Share.Value = ed25519.RandomScalar()
}

// PerturbDecommitment modifies the given verifiable share to have a random
// decommitment value.
func PerturbDecommitment(vs *ed25519.VerifiableShare) {
	vs.Decommitment = ed25519.RandomScalar()
}

// VsharesAreConsistent is a wrapper around SharesAreConsistent for the
// VerifiableShares type.
func VsharesAreConsistent(
	vshares ed25519.VerifiableShares,
	k int,
) bool {
	return SharesAreConsistent(vshares.Shares(), k)
}

func MarshalUnmarshalCheck(t reflect.Type) error {
	// Generate
	x, ok := quick.Value(t, rand.New(rand.NewSource(time.Now().UnixNano())))
	if !ok {
		return fmt.Errorf("cannot generate value of type %v", t)
	}
	// Marshal
	data, err := surge.ToBinary(x.Interface())
	if err != nil {
		return fmt.Errorf("cannot marshal: %v", err)
	}
	// Unmarshal
	y := reflect.New(t)
	if err := surge.FromBinary(y.Interface(), data); err != nil {
		return fmt.Errorf("cannot unmarshal: %v", err)
	}
	// Equality
	if !reflect.DeepEqual(x.Interface(), y.Elem().Interface()) {
		arr := make([]reflect.Value, 1)
		arr[0] = reflect.ValueOf(y)
		v := reflect.ValueOf(x).MethodByName("Eq").Call(arr)
		if !v[0].Bool() {
			return fmt.Errorf("unequal")
		}
	}
	return nil
}
