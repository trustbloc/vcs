/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/vcs/test/bdd/pkg/common"
	bddctx "github.com/trustbloc/vcs/test/bdd/pkg/context"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/oidc4vc"
	"github.com/trustbloc/vcs/test/bdd/pkg/v1/oidc4vp"
	vcv1 "github.com/trustbloc/vcs/test/bdd/pkg/v1/vc"
	vc_devapi "github.com/trustbloc/vcs/test/bdd/pkg/vc-devapi"
	vc_echo "github.com/trustbloc/vcs/test/bdd/pkg/vc-echo"
)

const (
	composeDir      = "./fixtures/"
	composeFilePath = composeDir + "docker-compose.yml"
)

var logger = log.New("vcs-bdd")

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all but excluding those marked with @wip
	tags := "@all && ~@wip"

	if os.Getenv("TAGS") != "" {
		tags = os.Getenv("TAGS")
	}

	flag.Parse()

	format := "progress"
	if getCmdArg("test.v") == "true" {
		format = "pretty"
	}

	runArg := getCmdArg("test.run")
	if runArg != "" {
		tags = runArg
	}

	status := runBDDTests(tags, format)

	os.Exit(status)
}

func getCmdArg(argName string) string {
	cmdTags := flag.CommandLine.Lookup(argName)
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		return cmdTags.Value.String()
	}

	return ""
}

func runBDDTests(tags, format string) int {
	return godog.TestSuite{
		Name:                 "VC services test suite",
		TestSuiteInitializer: initializeTestSuite,
		ScenarioInitializer:  initializeScenario,
		Options:              buildOptions(tags, format),
	}.Run()
}

func initializeTestSuite(ctx *godog.TestSuiteContext) {
	if os.Getenv("DISABLE_COMPOSITION") == "true" {
		return
	}

	ctx.BeforeSuite(beforeSuiteHook)
	ctx.AfterSuite(afterSuiteHook)
}

func beforeSuiteHook() {
	if os.Getenv("DISABLE_COMPOSE") == "true" {
		return
	}

	dockerComposeUp := []string{"docker-compose", "-f", composeFilePath, "up", "--force-recreate", "-d"}

	logger.Info("Running ", log.WithDockerComposeCmd(strings.Join(dockerComposeUp, " ")))

	cmd := exec.Command(dockerComposeUp[0], dockerComposeUp[1:]...) //nolint:gosec
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Fatal("bdd test beforeSuiteHook", log.WithCommand(string(out)), log.WithError(err))
	}

	testSleep := 60

	if os.Getenv("TEST_SLEEP") != "" {
		s, err := strconv.Atoi(os.Getenv("TEST_SLEEP"))
		if err != nil {
			logger.Error("invalid 'TEST_SLEEP'", log.WithError(err))
		} else {
			testSleep = s
		}
	}

	sleepD := time.Second * time.Duration(testSleep)
	logger.Info("*** testSleep", log.WithSleep(sleepD))
	time.Sleep(sleepD)
}

func afterSuiteHook() {
	if os.Getenv("DISABLE_COMPOSE") == "true" {
		return
	}

	dockerComposeDown := []string{"docker-compose", "-f", composeFilePath, "down"}

	logger.Info(fmt.Sprintf("Running %s", strings.Join(dockerComposeDown, " ")))

	cmd := exec.Command(dockerComposeDown[0], dockerComposeDown[1:]...) //nolint:gosec
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Fatal("bdd test afterSuiteHook", log.WithCommand(string(out)), log.WithError(err))
	}
}

type feature interface {
	// RegisterSteps registers scenario steps.
	RegisterSteps(sc *godog.ScenarioContext)
}

func initializeScenario(sc *godog.ScenarioContext) {
	bddContext, err := bddctx.NewBDDContext("fixtures/keys/tls/ec-cacert.pem", "./testdata",
		"fixtures/profile/profiles.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize BDD context: %s", err.Error()))
	}

	oidc4vcSteps, err := oidc4vc.NewSteps(bddContext)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize OIDC4VC steps: %s", err.Error()))
	}

	features := []feature{
		common.NewSteps(bddContext),
		vcv1.NewSteps(bddContext),
		oidc4vcSteps,
		oidc4vp.NewSteps(bddContext),
		vc_echo.NewSteps(bddContext),
		vc_devapi.NewSteps(bddContext),
	}

	for _, f := range features {
		f.RegisterSteps(sc)
	}
}

func buildOptions(tags, format string) *godog.Options {
	return &godog.Options{
		Tags:          tags,
		Format:        format,
		Strict:        true,
		StopOnFailure: true,
	}
}
