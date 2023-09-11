/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formatter

import (
	"fmt"
	"io"
	"strings"
)

type JWTFormatter struct{}

// Match JSON media type.
func (j *JWTFormatter) Match(mediatype string) bool {
	return strings.HasPrefix(mediatype, "application/jwt")
}

// Format JSON content.
func (j *JWTFormatter) Format(w io.Writer, src []byte) error {
	_, err := w.Write(src)
	if err != nil {
		return fmt.Errorf("unable to write JWT: %w", err)
	}

	return nil
}
