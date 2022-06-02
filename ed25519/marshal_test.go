package ed25519_test

import (
	"fmt"
	"github.com/renproject/shamir/ed25519/shamirutil"
	"github.com/renproject/surge/surgeutil"
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/shamir/ed25519"
	. "github.com/renproject/shamir/secp256k1/shamirutil"
)

var _ = Describe("Surge marshalling", func() {
	trials := 100
	types := []reflect.Type{
		reflect.TypeOf(Share{}),
		reflect.TypeOf(Shares{}),
		reflect.TypeOf(Commitment{}),
		reflect.TypeOf(VerifiableShare{}),
		reflect.TypeOf(VerifiableShares{}),
	}

	for _, t := range types {
		t := t

		Context(fmt.Sprintf("surge marshalling and unmarshalling for %v", t), func() {
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
	for _, t := range types {
		t := t
		if t != reflect.TypeOf(Commitment{}) {
			Context(fmt.Sprintf("surge marshalling and unmarshalling for %v", t), func() {
				It("should be the same after marshalling and unmarshalling", func() {
					for i := 0; i < trials; i++ {
						Expect(surgeutil.MarshalUnmarshalCheck(t)).To(Succeed())
					}
				})
			})
		}
	}
	Context("surge marshalling and unmarshalling for Commitment{}", func() {
		It("should be the same after marshalling and unmarshalling", func() {
			for i := 0; i < trials; i++ {
				commit := shamirutil.RandomCommitment(RandRange(10, 20))
				newcommit := make(Commitment, len(commit))
				rem := 4 + PointSizeMarshalled*len(commit)
				dst := make([]byte, rem)
				_, _, err := commit.Marshal(dst, rem)
				Expect(err).ToNot(HaveOccurred())
				rem = 4 + PointSize*len(commit)
				_, _, err = newcommit.Unmarshal(dst, rem)
				Expect(err).ToNot(HaveOccurred())
				Expect(newcommit.Eq(commit)).To(BeTrue())
			}
		})
	})
	Context("surge marshalling and unmarshalling for ed25519 Point{}", func() {
		It("should be the same after marshalling and unmarshalling", func() {
			for i := 0; i < trials; i++ {
				var newpoint Point
				point := RandomPoint()
				rem := PointSize
				dst := make([]byte, rem)
				_, _, err := point.Marshal(dst, rem)
				Expect(err).ToNot(HaveOccurred())
				_, _, err = newpoint.Unmarshal(dst[:], rem)
				Expect(err).ToNot(HaveOccurred())
				Expect(newpoint.Eq(&point)).To(BeTrue())
			}
		})
	})
})
