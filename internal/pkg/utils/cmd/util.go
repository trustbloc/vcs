/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// GetUserSetOptionalVarFromString returns values either command line flag or environment variable.
func GetUserSetOptionalVarFromString(cmd *cobra.Command, flagName, envKey string) string {
	//nolint // the error will not happen for optional var
	v, _ := GetUserSetVarFromString(cmd, flagName, envKey, true)

	return v
}

// GetUserSetVarFromString returns values either command line flag or environment variable.
func GetUserSetVarFromString(cmd *cobra.Command, flagName, envKey string, isOptional bool) (string, error) {
	if cmd.Flags().Changed(flagName) {
		value, err := cmd.Flags().GetString(flagName)
		if err != nil {
			return "", fmt.Errorf(flagName+" flag not found: %s", err)
		}

		if value == "" {
			return "", fmt.Errorf("%s value is empty", flagName)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)

	if isOptional || isSet {
		if !isOptional && value == "" {
			return "", fmt.Errorf("%s value is empty", envKey)
		}

		return value, nil
	}

	return "", errors.New("Neither " + flagName + " (command line flag) nor " + envKey +
		" (environment variable) have been set.")
}

// GetUserSetOptionalVarFromArrayString returns the variables set via either command line flag or environment variable.
// If both are set, then the command line flag takes precedence.
// For the command line flag, the variables must be set using repeated flags (e.g. --flagName value1 --flagName value2).
// For the environment variable, the variables are parsed as comma-separated-values (CSV) and returned as a slice.
// The command line flag must be set as a StringArray.
// If the variable isn't set, then an empty or nil slice will be returned.
func GetUserSetOptionalVarFromArrayString(cmd *cobra.Command, flagName, envKey string) []string {
	//nolint // reason the error will not happen for optional var
	v, _ := GetUserSetVarFromArrayString(cmd, flagName, envKey, true)

	return v
}

// GetUserSetVarFromArrayString returns the variables set via either command line flag or environment variable.
// If both are set, then the command line flag takes precedence.
// For the command line flag, the variables must be set using repeated flags (e.g. --flagName value1 --flagName value2).
// For the environment variable, the variables are parsed as comma-separated-values (CSV) and returned as a slice.
// The command line flag must be set as a StringArray.
// If the variable isn't set, then an error will be returned.
func GetUserSetVarFromArrayString(cmd *cobra.Command, flagName, envKey string, isOptional bool) ([]string, error) {
	if cmd.Flags().Changed(flagName) {
		value, err := cmd.Flags().GetStringArray(flagName)
		if err != nil {
			return nil, fmt.Errorf(flagName+" flag not found: %s", err)
		}

		if len(value) == 0 {
			return nil, fmt.Errorf("%s value is empty", flagName)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)

	if isOptional || isSet {
		if !isOptional && value == "" {
			return nil, fmt.Errorf("%s value is empty", envKey)
		}

		if value == "" {
			return []string{}, nil
		}

		return strings.Split(value, ","), nil
	}

	return nil, errors.New("Neither " + flagName + " (command line flag) nor " + envKey +
		" (environment variable) have been set.")
}

// GetUserSetOptionalCSVVar returns the variables set via either command line flag or environment variable.
// If both are set, then the command line flag takes precedence.
// The variables are parsed as comma-separated-values (CSV) and returned as a slice.
// The command line flag must be set as a StringSlice.
// If the variable isn't set, then a nil slice will be returned.
func GetUserSetOptionalCSVVar(cmd *cobra.Command, flagName, envKey string) []string {
	//nolint // For an optional variable, no error will happen (or we don't care about the error)
	v, _ := GetUserSetCSVVar(cmd, flagName, envKey, true)

	return v
}

// GetUserSetCSVVar returns the variables set via either command line flag or environment variable.
// If both are set, then the command line flag takes precedence.
// The variables are parsed as comma-separated-values (CSV) and returned as a slice.
// The command line flag must be set as a StringSlice.
// If the variable isn't set, then an error will be returned.
func GetUserSetCSVVar(cmd *cobra.Command, flagName, envKey string, isOptional bool) ([]string, error) {
	if cmd.Flags().Changed(flagName) {
		value, err := cmd.Flags().GetStringSlice(flagName)
		if err != nil {
			return nil, fmt.Errorf(flagName+" flag not found: %s", err)
		}

		if len(value) == 0 {
			return nil, fmt.Errorf("%s value is empty", flagName)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)

	if isOptional || isSet {
		if !isOptional && value == "" {
			return nil, fmt.Errorf("%s value is empty", envKey)
		}

		if value == "" {
			return nil, nil
		}

		return strings.Split(value, ","), nil
	}

	return nil, errors.New("Neither " + flagName + " (command line flag) nor " + envKey +
		" (environment variable) have been set.")
}
