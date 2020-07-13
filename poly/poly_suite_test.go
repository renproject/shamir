package poly_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPoly(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Poly Suite")
}
