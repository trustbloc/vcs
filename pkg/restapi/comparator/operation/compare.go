/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustbloc/edge-service/pkg/client/csh/client/operations"
	cshclientmodels "github.com/trustbloc/edge-service/pkg/client/csh/models"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation/models"
)

// HandleEqOp handles a ComparisonRequest using the EqOp operator.
func (o *Operation) HandleEqOp(w http.ResponseWriter, op *models.EqOp) { //nolint: funlen
	queries := make([]models.Query, 0)

	for i := range op.Args() {
		query := op.Args()[i]

		switch q := query.(type) {
		case *models.DocQuery:
			docMeta, err := o.vaultClient.GetDocMetaData(*q.VaultID, *q.DocID)
			if err != nil {
				respondErrorf(w, http.StatusInternalServerError, "failed to get doc meta: %s", err.Error())

				return
			}

			parts := strings.Split(docMeta.URI, "/")

			vaultID := parts[len(parts)-3]
			docID := parts[len(parts)-1]

			kmsURL, err := url.Parse(docMeta.EncKeyURI)
			if err != nil {
				respondErrorf(w, http.StatusInternalServerError, "failed to parse url: %s", err.Error())

				return
			}

			edvURL, err := url.Parse(docMeta.URI)
			if err != nil {
				respondErrorf(w, http.StatusInternalServerError, "failed to parse url: %s", err.Error())

				return
			}

			queries = append(queries, &cshclientmodels.DocQuery{VaultID: &vaultID, DocID: &docID,
				UpstreamAuth: &cshclientmodels.DocQueryAO1UpstreamAuth{
					Edv: &cshclientmodels.UpstreamAuthorization{
						BaseURL: fmt.Sprintf("%s://%s/%s", edvURL.Scheme, edvURL.Host, parts[3]),
						Zcap:    q.AuthTokens.Edv,
					},
					Kms: &cshclientmodels.UpstreamAuthorization{
						BaseURL: fmt.Sprintf("%s://%s", kmsURL.Scheme, kmsURL.Host),
						Zcap:    q.AuthTokens.Kms,
					},
				}})

			// TODO get query id for orgCompQueryZCAP

		case *models.AuthorizedQuery:
			respondErrorf(w, http.StatusNotImplemented, "'RefQuery' not yet implemented by 'EqOp'")

			return
		}
	}

	cshOP := &models.EqOp{}
	cshOP.SetArgs(queries)

	request := &cshclientmodels.ComparisonRequest{}
	request.SetOp(cshOP)

	response, err := o.cshClient.PostCompare(
		operations.NewPostCompareParams().
			WithTimeout(requestTimeout).
			WithRequest(request),
	)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError, "failed to execute comparison: %s", err)

		return
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respond(w, http.StatusOK, headers, models.ComparisonResult{Result: response.Payload.Result})
}
