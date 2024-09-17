/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"bytes"
	"context"
	"text/template"
	"time"

	"github.com/google/uuid"
	util "github.com/trustbloc/did-go/doc/util/time"
	"github.com/trustbloc/vc-go/verifiable"
)

type CredentialComposer struct {
}

func NewCredentialComposer() *CredentialComposer {
	return &CredentialComposer{}
}

func (c *CredentialComposer) Compose(
	_ context.Context,
	credential *verifiable.Credential,
	req *PrepareCredentialsRequest,
) (*verifiable.Credential, error) {
	if req == nil || req.CredentialConfiguration == nil ||
		req.CredentialConfiguration.CredentialComposeConfiguration == nil {
		return credential, nil
	}

	if idTemplate := req.CredentialConfiguration.CredentialComposeConfiguration.IDTemplate; idTemplate != "" {
		params := c.baseParams(req)
		params["CredentialID"] = credential.Contents().ID

		id, err := c.renderRaw(idTemplate, params)
		if err != nil {
			return nil, err
		}

		credential = credential.WithModifiedID(id)
	}

	if req.CredentialConfiguration.CredentialComposeConfiguration.OverrideIssuer {
		issuer := credential.Contents().Issuer
		if issuer == nil {
			issuer = &verifiable.Issuer{}
		}

		issuer.ID = req.IssuerDID

		credential = credential.WithModifiedIssuer(issuer)
	}

	if req.CredentialConfiguration.CredentialComposeConfiguration.OverrideSubjectDID {
		var newSubjects []verifiable.Subject
		for _, s := range credential.Contents().Subject {
			s.ID = req.SubjectDID

			newSubjects = append(newSubjects, s)
		}

		credential = credential.WithModifiedSubject(newSubjects)
	}

	if credential.Contents().Expired == nil && req.CredentialConfiguration.CredentialExpiresAt != nil {
		if verifiable.IsBaseContext(credential.Contents().Context, verifiable.V2ContextURI) {
			credential = credential.WithModifiedValidUntil(util.NewTime(*req.CredentialConfiguration.CredentialExpiresAt))
		} else {
			credential = credential.WithModifiedExpired(util.NewTime(*req.CredentialConfiguration.CredentialExpiresAt))
		}
	}

	if credential.Contents().Issued == nil {
		if verifiable.IsBaseContext(credential.Contents().Context, verifiable.V2ContextURI) {
			credential = credential.WithModifiedValidFrom(util.NewTime(time.Now().UTC()))
		} else {
			credential = credential.WithModifiedIssued(util.NewTime(time.Now().UTC()))
		}
	}

	return credential, nil
}

func (c *CredentialComposer) baseParams(
	tx *PrepareCredentialsRequest,
) map[string]interface{} {
	result := map[string]interface{}{
		"RandomID":  uuid.NewString(),
		"TxID":      tx.TxID,
		"IssuerDID": tx.IssuerDID,
	}

	return result
}

func (c *CredentialComposer) renderRaw(
	templateStr string,
	param map[string]interface{},
) (string, error) {
	tpl, err := template.New(uuid.NewString()).Parse(templateStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err = tpl.Execute(&buf, param); err != nil {
		return "", err
	}

	return buf.String(), nil
}
