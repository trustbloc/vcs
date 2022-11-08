/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oauth2client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

const (
	defaultLength = 56
	defaultMethod = "S256"
)

func (c *Client) GeneratePKCE() (string, string, string, error) {
	b := make([]byte, defaultLength)
	_, err := rand.Read(b)

	if err != nil {
		return "", "", "", err
	}

	return c.GeneratePKCEFromBytes(b)
}

func (c *Client) GeneratePKCEFromBytes(b []byte) (string, string, string, error) {
	verifier := c.encode(b)

	h := sha256.New()
	h.Write([]byte(verifier))
	challenge := c.encode(h.Sum(nil))

	return verifier, challenge, defaultMethod, nil
}

func (c *Client) encode(data []byte) string {
	encoded := strings.ReplaceAll(base64.StdEncoding.EncodeToString(data), "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	encoded = strings.ReplaceAll(encoded, "=", "")

	return encoded
}
