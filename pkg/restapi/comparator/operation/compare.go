/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/http"

	"github.com/trustbloc/edge-service/pkg/restapi/comparator/operation/openapi"
)

// HandleEqOp handles a ComparisonRequest using the EqOp operator.
func (o *Operation) HandleEqOp(w http.ResponseWriter, op *openapi.EqOp) {
	comparison := &openapi.ComparisonResult{Result: true}

	for i := range op.Args() {
		query := op.Args()[i]

		switch q := query.(type) {
		case *openapi.DocQuery:
			docMeta, err := o.vaultClient.GetDocMetaData(*q.VaultID, *q.DocID)
			if err != nil {
				respondErrorf(w, http.StatusInternalServerError, "failed to get doc meta: %s", err.Error())

				return
			}

			logger.Infof(docMeta.URI)

			// TODO where to put docMeta URI in doc query struct for doc1

			// TODO how to get query id for doc2 from orgCompQueryZCAP

			// TODO call csh with docMeta URI for doc1 and query id for doc2

		case *openapi.AuthorizedQuery:
			respondErrorf(w, http.StatusNotImplemented, "'RefQuery' not yet implemented by 'EqOp'")

			return
		}
	}

	respond(w, http.StatusOK, nil, comparison)
}
