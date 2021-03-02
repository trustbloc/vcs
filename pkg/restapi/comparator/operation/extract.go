/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/http"
	"strings"

	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/edge-service/pkg/client/csh/client/operations"
	cshclientmodels "github.com/trustbloc/edge-service/pkg/client/csh/models"
	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation/models"
)

// HandleExtract handles extract req.
func (o *Operation) HandleExtract(w http.ResponseWriter, extract *models.Extract) {
	queries := make([]cshclientmodels.Query, 0)

	for _, query := range extract.Queries() {
		q, ok := query.(*models.AuthorizedQuery)
		if !ok {
			respondErrorf(w, http.StatusNotImplemented, "unsupported query type: %s", query.Type())

			return
		}

		orgZCAP, err := zcapld.DecompressZCAP(*q.AuthToken)
		if err != nil {
			respondErrorf(w, http.StatusInternalServerError, "failed to parse org zcap: %s", err.Error())

			return
		}

		queryPath := strings.Split(orgZCAP.InvocationTarget.ID, "/queries/")

		refQuery := &cshclientmodels.RefQuery{Ref: &queryPath[1]}
		refQuery.SetID(query.ID())

		queries = append(queries, refQuery)
	}

	extractions, err := o.cshClient.PostExtract(
		operations.NewPostExtractParams().
			WithTimeout(requestTimeout).
			WithRequest(queries),
	)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError, "failed to execute extract: %s", err)

		return
	}

	response := models.ExtractResp{}

	for i := range extractions.Payload {
		extraction := extractions.Payload[i]

		response.Documents = append(response.Documents, &models.ExtractRespDocumentsItems0{
			ID:       extraction.ID,
			Contents: extraction.Document,
		})
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respond(w, http.StatusOK, headers, response)
}
