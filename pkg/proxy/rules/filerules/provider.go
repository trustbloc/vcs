/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package filerules

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("edge-service-proxy-provider")

// Config describes file configuration
type Config struct {
	Rules []Rule `json:"rules"`
}

// Rule contains rule information (from config file)
type Rule struct {
	Pattern string `json:"pattern"`
	URL     string `json:"url"`
}

// PatternRule hods config rule + compiled pattern
type PatternRule struct {
	Pattern *regexp.Regexp
	Rule
}

// Provider applies rules to requested URI
type Provider struct {
	patternRules []PatternRule
}

// New returns new proxy rules provider from file
func New(configFile string) (*Provider, error) {
	data, err := ioutil.ReadFile(configFile) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s' : %w", configFile, err)
	}

	patternRules, err := getPatternRules(data)
	if err != nil {
		return nil, err
	}

	return &Provider{patternRules: patternRules}, nil
}

// Transform calculates destination URL based on input and proxy rules
func (p *Provider) Transform(source string) (string, error) {
	// For each match of the regex in the content
	for _, rule := range p.patternRules {
		var result []byte
		// for each match of the regex in the content
		for _, submatchIndexes := range rule.Pattern.FindAllStringSubmatchIndex(source, -1) {
			if rule.URL == "" {
				return "", nil
			}

			// apply the captured submatches to the template and append the output to the result
			result = rule.Pattern.ExpandString(result, rule.URL, source, submatchIndexes)
		}

		if len(result) > 0 {
			return string(result), nil
		}
	}

	return "", errors.New("no match")
}

func getPatternRules(data []byte) ([]PatternRule, error) {
	var cfg Config

	err := json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal proxy config file: %w", err)
	}

	var patternRules []PatternRule

	for _, rule := range cfg.Rules {
		r, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile rule pattern: %s", rule.Pattern)
		}

		patternRules = append(patternRules, PatternRule{
			Pattern: r,
			Rule:    rule,
		})
	}

	if len(patternRules) == 0 {
		logger.Warnf("no proxy rules have been configured")
	}

	return patternRules, nil
}
