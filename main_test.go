//go:build integration

package main

import (
	"os"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
	"go.uber.org/zap"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	solver := VultrSolver{logger: logger}
	fixture := acmetest.NewFixture(&solver,
		acmetest.SetResolvedZone(zone),
		acmetest.SetManifestPath("testdata/"),
		acmetest.SetUseAuthoritative(true),
	)
	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	//fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)
}
