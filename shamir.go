package shamir

import (
	"fmt"

	"github.com/renproject/secp256k1-go"
)

type Shares []Share

type Share struct {
	index secp256k1.Secp256k1N
	value secp256k1.Secp256k1N
}

func NewShare(index secp256k1.Secp256k1N, value secp256k1.Secp256k1N) Share {
	return Share{index, value}
}

func (s *Share) Index() secp256k1.Secp256k1N {
	return s.index
}

func (s *Share) Value() secp256k1.Secp256k1N {
	return s.value
}

func (s *Share) IndexEq(other *secp256k1.Secp256k1N) bool {
	return s.index.Eq(other)
}

type Sharer struct {
	indices []secp256k1.Secp256k1N
	coeffs  []secp256k1.Secp256k1N
}

func NewSharer(indices []secp256k1.Secp256k1N) Sharer {
	coeffs := make([]secp256k1.Secp256k1N, len(indices))
	return Sharer{indices, coeffs}
}

func (sharer *Sharer) Share(secret secp256k1.Secp256k1N, k int) (Shares, error) {
	if k > len(sharer.indices) {
		return nil, fmt.Errorf(
			"reconstruction threshold too large: expected k <= %v, got k = %v",
			len(sharer.indices), k,
		)
	}

	// Set coefficients
	sharer.coeffs = sharer.coeffs[:k]
	sharer.coeffs[0] = secret
	for i := 1; i < len(sharer.coeffs); i++ {
		sharer.coeffs[i] = secp256k1.RandomSecp256k1N()
	}

	// Crate shares
	shares := make(Shares, len(sharer.indices))
	var eval secp256k1.Secp256k1N
	for i, ind := range sharer.indices {
		eval.Set(&sharer.coeffs[k-1])
		for j := k - 2; j >= 0; j-- {
			eval.Mul(&eval, &ind)
			eval.Add(&eval, &sharer.coeffs[j])
		}
		eval.Normalize()
		shares[i] = NewShare(ind, eval)
	}

	return shares, nil
}

type Reconstructor struct {
	indices  []secp256k1.Secp256k1N
	fullProd []secp256k1.Secp256k1N
	indInv   []secp256k1.Secp256k1N
	indInts  []int
	seen     []bool
}

func NewReconstructor(indices []secp256k1.Secp256k1N) Reconstructor {
	fullProd := make([]secp256k1.Secp256k1N, len(indices))
	indInv := make([]secp256k1.Secp256k1N, len(indices))
	indInts := make([]int, len(indices))
	seen := make([]bool, len(indices))

	var neg, inv secp256k1.Secp256k1N
	for i := range indices {
		fullProd[i] = secp256k1.OneSecp256k1N()
		neg.Neg(&indices[i], 1)
		for j := range indices {
			if i == j {
				continue
			}

			inv.Add(&indices[j], &neg)
			inv.Inv(&inv)
			inv.Mul(&inv, &indices[j])

			fullProd[i].Mul(&fullProd[i], &inv)
		}
	}

	for i, ind := range indices {
		indInv[i].Inv(&ind)
	}

	return Reconstructor{indices, fullProd, indInv, indInts, seen}
}

func (r *Reconstructor) Open(shares Shares) (secp256k1.Secp256k1N, error) {
	var secret secp256k1.Secp256k1N

	// Check if there are any shares with indices that don't exist in
	// r.indices. If so, reconstruction will return an incorrect value, so
	// return an error instead
	if len(shares) > len(r.indices) {
		return secret, fmt.Errorf(
			"too many shares: expected len(shares) <= %v, got len(shares) = %b",
			len(r.indices), len(shares),
		)
	}

	// Map the shares onto the corresponding indices in r.indices
	r.indInts = r.indInts[:len(shares)]
OUTER:
	for i, share := range shares {
		for j, ind := range r.indices {
			if share.IndexEq(&ind) {
				r.indInts[i] = j
				continue OUTER
			}
		}

		return secret, fmt.Errorf(
			"unexpected share index: share has index %v which is out of the index set",
			share.Index(),
		)
	}

	// Check if any of the shares have the same index. This is incorrect input,
	// and so an error will be returned
	for i := range r.seen {
		r.seen[i] = false
	}
	for _, ind := range r.indInts {
		if r.seen[ind] {
			return secret, fmt.Errorf(
				"shares must have distinct indices: two shares have index %v",
				r.indices[ind].Int(),
			)
		}
		r.seen[ind] = true
	}

	complement := make([]int, len(r.indices))
	for i := range complement {
		complement[i] = 1
	}

	// Get the corresponding indices for the given shares
	for _, ind := range r.indInts {
		complement[ind] = 0
	}
	var toggle int
	for i, j := 0, 0; i < len(r.indices); i++ {
		toggle = complement[i]
		complement[j] = toggle * i
		j += toggle
	}
	complement = complement[:len(r.indices)-len(shares)]

	var term, diff secp256k1.Secp256k1N
	for i, share := range shares {
		term = share.Value()
		term.Mul(&term, &r.fullProd[r.indInts[i]])
		for _, j := range complement {
			diff.Neg(&r.indices[r.indInts[i]], 1)
			diff.Add(&r.indices[j], &diff)
			term.Mul(&term, &diff)
			term.Mul(&term, &r.indInv[j])
		}
		secret.Add(&secret, &term)
	}
	secret.Normalize()

	return secret, nil
}
