package polyutil

import (
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir/poly"
)

// SetRandomPolynomial sets the given polynomial to be a random polynomial with
// the given degree.
func SetRandomPolynomial(dst *poly.Poly, degree int) {
	// Make all memory available to be accessed.
	*dst = (*dst)[:cap(*dst)]

	// Fill entire memory with random values, as even memory locations
	// beyond the degree can contain non zero values in practice.
	for i := range *dst {
		(*dst)[i] = secp256k1.RandomFn()
	}

	// Ensure that the leading term is non-zero.
	for dst.Coefficient(degree).IsZero() {
		(*dst)[degree] = secp256k1.RandomFn()
	}

	// Set degree.
	*dst = (*dst)[:degree+1]
}
