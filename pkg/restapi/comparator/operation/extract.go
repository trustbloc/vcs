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

	for _, token := range extract.AuthTokens {
		orgZCAP, err := zcapld.DecompressZCAP(token)
		if err != nil {
			respondErrorf(w, http.StatusInternalServerError, "failed to parse org zcap: %s", err.Error())

			return
		}

		queryPath := strings.Split(orgZCAP.InvocationTarget.ID, "/queries/")

		queries = append(queries, &cshclientmodels.RefQuery{Ref: &queryPath[1]})
	}

	response, err := o.cshClient.PostExtract(
		operations.NewPostExtractParams().
			WithTimeout(requestTimeout).
			WithRequest(queries),
	)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError, "failed to execute extract: %s", err)

		return
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respond(w, http.StatusOK, headers, models.ExtractResp{Documents: response.Payload})
}
