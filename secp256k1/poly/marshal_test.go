package poly_test

import (
	"fmt"
	"reflect"

	"github.com/renproject/surge/surgeutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir/secp256k1/poly"
)

var _ = Describe("Surge marshalling", func() {
	trials := 100
	types := []reflect.Type{
		reflect.TypeOf(Poly{}),
		reflect.TypeOf(Interpolator{}),
	}

	for _, t := range types {
		t := t

		Context(fmt.Sprintf("surge marshalling and unmarshalling for %v", t), func() {
			It("should be the same after marshalling and unmarshalling", func() {
				for i := 0; i < trials; i++ {
					Expect(surgeutil.MarshalUnmarshalCheck(t)).To(Succeed())
				}
			})

			It("should not panic when fuzzing", func() {
				for i := 0; i < trials; i++ {
					Expect(func() { surgeutil.Fuzz(t) }).ToNot(Panic())
				}
			})

			Context("marshalling", func() {
				It("should return an error when the buffer is too small", func() {
					for i := 0; i < trials; i++ {
						Expect(surgeutil.MarshalBufTooSmall(t)).To(Succeed())
					}
				})

				It("should return an error when the memory quota is too small", func() {
					for i := 0; i < trials; i++ {
						Expect(surgeutil.MarshalRemTooSmall(t)).To(Succeed())
					}
				})
			})

			Context("unmarshalling", func() {
				It("should return an error when the buffer is too small", func() {
					for i := 0; i < trials; i++ {
						Expect(surgeutil.UnmarshalBufTooSmall(t)).To(Succeed())
					}
				})

				It("should return an error when the memory quota is too small", func() {
					for i := 0; i < trials; i++ {
						Expect(surgeutil.UnmarshalRemTooSmall(t)).To(Succeed())
					}
				})
			})
		})
	}
})
