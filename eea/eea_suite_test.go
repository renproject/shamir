package eea_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestEea(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Eea Suite")
}
