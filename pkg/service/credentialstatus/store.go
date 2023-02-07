/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentialstatus

type CSLStore interface {
	GetCSLWrapperURL(issuerProfileURL, issuerProfileID, statusID string) (string, error)
	Upsert(cslWrapper *CSLWrapper) error
	Get(cslWrapperURL string) (*CSLWrapper, error)
	UpdateLatestListID(id int) error
	GetLatestListID() (int, error)
}
