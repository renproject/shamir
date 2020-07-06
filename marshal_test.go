package shamir_test

import (
	"fmt"
	"reflect"

	"github.com/renproject/surge/surgeutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir"
)

var _ = Describe("Surge marshalling", func() {
	trials := 100
	types := []reflect.Type{
		reflect.TypeOf(Share{}),
		reflect.TypeOf(Shares{}),
		reflect.TypeOf(Sharer{}),
		reflect.TypeOf(Reconstructor{}),
		reflect.TypeOf(Commitment{}),
		reflect.TypeOf(VerifiableShare{}),
		reflect.TypeOf(VerifiableShares{}),
		reflect.TypeOf(VSSChecker{}),
		reflect.TypeOf(VSSharer{}),
	}

	Context(fmt.Sprintf("surge"), func() {
		It("should be the same after marshalling and unmarshalling", func() {
			for i := 0; i < trials; i++ {
				for _, t := range types {
					Expect(surgeutil.MarshalUnmarshalCheck(t)).To(Succeed())
				}
			}
		})

		It("should not panic when fuzzing", func() {
			for i := 0; i < trials; i++ {
				for _, t := range types {
					Expect(func() { surgeutil.Fuzz(t) }).ToNot(Panic())
				}
			}
		})

		Context("marshalling", func() {
			It("should return an error when the buffer is too small", func() {
				for i := 0; i < trials; i++ {
					for _, t := range types {
						Expect(surgeutil.MarshalBufTooSmall(t)).To(Succeed())
					}
				}
			})

			It("should return an error when the memory quota is too small", func() {
				for i := 0; i < trials; i++ {
					for _, t := range types {
						Expect(surgeutil.MarshalRemTooSmall(t)).To(Succeed())
					}
				}
			})
		})

		Context("unmarshalling", func() {
			It("should return an error when the buffer is too small", func() {
				for i := 0; i < trials; i++ {
					for _, t := range types {
						Expect(surgeutil.UnmarshalBufTooSmall(t)).To(Succeed())
					}
				}
			})

			It("should return an error when the memory quota is too small", func() {
				for i := 0; i < trials; i++ {
					for _, t := range types {
						Expect(surgeutil.UnmarshalRemTooSmall(t)).To(Succeed())
					}
				}
			})
		})
	})
})
