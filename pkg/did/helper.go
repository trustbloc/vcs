/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// VerificationMethods returns the first verification method encountered for all relations in the same given order.
// At least one relation must be provided.
func VerificationMethods(d *did.Doc, relations ...did.VerificationRelationship) ([]*did.VerificationMethod, error) {
	vm := make([]*did.VerificationMethod, 0)

	for _, relation := range relations {
		methods := d.VerificationMethods(relation)[relation]

		if len(methods) == 0 {
			return nil, fmt.Errorf("did %s does not have a verification method for relation %d", d.ID, relation)
		}

		vm = append(vm, &methods[0].VerificationMethod)
	}

	return vm, nil
}

// Fragments parses each url and returns the fragments in the same order.
func Fragments(didURLs ...string) ([]string, error) {
	f := make([]string, len(didURLs))

	for i, didURL := range didURLs {
		u, err := url.Parse(didURL)
		if err != nil {
			return nil, fmt.Errorf("not a URL: %s", didURL)
		}

		if u.Fragment == "" {
			return nil, fmt.Errorf("no fragment in url %s", didURL)
		}

		f[i] = u.Fragment
	}

	return f, nil
}
