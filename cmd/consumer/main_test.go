package main

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestIdentConsumer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Privacy Consumer Suite")
}

var _ = Describe("Main", func() {

})