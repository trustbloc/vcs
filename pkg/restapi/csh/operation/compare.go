/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/http"
	"reflect"

	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi/models"
)

func (o *Operation) handleEqOp(w http.ResponseWriter, eq *models.EqOp) {
	if len(eq.Args()) < 2 {
		respondErrorf(w, http.StatusBadRequest, "'EqOp' requires at least two arguments")

		return
	}

	comparison := &models.Comparison{Result: true}
	var prevDoc []byte

	for i, query := range eq.Args() {
		var document []byte
		var err error

		switch q := query.(type) {
		case *models.DocQuery:
			document, err = o.ReadDocQuery(q)
			if err != nil {
				// TODO discern specific error codes (can also be a bad zcap, bad url, etc)
				respondErrorf(w, http.StatusInternalServerError,
					"failed to read Confidential Storage document: %s", err.Error())

				return
			}
		case *models.RefQuery:
			respondErrorf(w, http.StatusNotImplemented, "'RefQuery' not yet implemented by 'EqOp'")

			return
		default:
			respondErrorf(w, http.StatusBadRequest, "invalid query type: %s", q.Type())

			return
		}

		if i == 0 {
			prevDoc = document

			continue
		}

		// TODO implement JSONPath

		comparison.Result = reflect.DeepEqual(prevDoc, document)
		if !comparison.Result {
			break
		}

		prevDoc = document
	}

	respond(w, http.StatusOK, nil, comparison)
}
