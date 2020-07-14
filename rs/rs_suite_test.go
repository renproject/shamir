package rs_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestRs(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Rs Suite")
}
