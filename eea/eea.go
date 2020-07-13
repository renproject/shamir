package eea

import (
	"github.com/renproject/shamir/poly"
)

// Stepper encapsulates the functionality of the Extended Euclidean Algorithm.
// It holds the internal state of the algorithm, and allows it to be stepped,
// and hence allows this state to be inspected at points in the algorithm
// before the canonical termination condition.
type Stepper struct {
	rPrev, rNext poly.Poly
	sPrev, sNext poly.Poly
	tPrev, tNext poly.Poly
	q, r         poly.Poly
}

// NewStepperWithCapacity constructs a new EEA algorithm object with the given
// capacity. The capacity should be at least as large as the capacity of the
// largerst polynomial that the EEA is to be performed with, otherwise
// executing the algorithm may cause a panic.
func NewStepperWithCapacity(c int) Stepper {
	rPrev, rNext := poly.NewWithCapacity(c), poly.NewWithCapacity(c)
	sPrev, sNext := poly.NewWithCapacity(c), poly.NewWithCapacity(c)
	tPrev, tNext := poly.NewWithCapacity(c), poly.NewWithCapacity(c)
	q, r := poly.NewWithCapacity(c), poly.NewWithCapacity(c)

	return Stepper{
		rPrev, rNext,
		sPrev, sNext,
		tPrev, tNext,
		q, r,
	}
}

// Rem returns a reference to the current remainder term for the EEA.
func (eea *Stepper) Rem() *poly.Poly {
	return &eea.rNext
}

// S returns a reference to the current s term for the EEA.
func (eea *Stepper) S() *poly.Poly {
	return &eea.sNext
}

// T returns a reference to the current t term for the EEA.
func (eea *Stepper) T() *poly.Poly {
	return &eea.tNext
}

// Init performs the initialisation of the state for the EEA for the given
// input polynomials. No steps in the algorithm are performed.
func (eea *Stepper) Init(a, b poly.Poly) {
	// r0 = a, r1 = b,
	eea.rPrev.Set(a)
	eea.rNext.Set(b)
	// s0 = 1, s1 = 0,
	eea.sPrev.Zero()
	eea.sPrev.Coefficient(0).SetU16(1)
	eea.sNext.Zero()
	// t0 = 0, t1 = 1
	eea.tPrev.Zero()
	eea.tNext.Zero()
	eea.tNext.Coefficient(0).SetU16(1)
}

// Step carries out one step of the EEA. It returns a boolean that is true when
// the state has reached the canonical termination condition (r_{k+1} = 0).
func (eea *Stepper) Step() bool {
	poly.Divide(eea.rPrev, eea.rNext, &eea.q, &eea.r)

	eea.rPrev.Set(eea.rNext)
	eea.rNext.Set(eea.r)

	// sNext, sPrev = sPrev - q * sNext, sNext
	eea.r.Mul(eea.q, eea.sNext)
	eea.r.Sub(eea.sPrev, eea.r)
	eea.sPrev.Set(eea.sNext)
	eea.sNext.Set(eea.r)

	// tNext, tPrev = tPrev - q * tNext, tNext
	eea.r.Mul(eea.q, eea.tNext)
	eea.r.Sub(eea.tPrev, eea.r)
	eea.tPrev.Set(eea.tNext)
	eea.tNext.Set(eea.r)

	return eea.rNext.IsZero()
}
