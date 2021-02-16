/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"net/http"
	"reflect"

	"github.com/trustbloc/edge-service/pkg/restapi/csh/operation/openapi"
)

// HandleEqOp handles a ComparisonRequest using the EqOp operator.
func (o *Operation) HandleEqOp(w http.ResponseWriter, op *openapi.EqOp) {
	const minArgs = 2

	if len(op.Args()) < minArgs {
		respondErrorf(w, http.StatusBadRequest, "'EqOp' requires at least two arguments")

		return
	}

	comparison := &openapi.Comparison{Result: true}

	var prevDoc []byte

	for i := range op.Args() {
		query := op.Args()[i]

		var (
			document []byte
			err      error
		)

		switch q := query.(type) {
		case *openapi.DocQuery:
			document, err = o.ReadDocQuery(q)
			if err != nil {
				// TODO discern specific error codes (can also be a bad zcap, bad url, etc)
				respondErrorf(w, http.StatusInternalServerError,
					"failed to read Confidential Storage document: %s", err.Error())

				return
			}
		case *openapi.RefQuery:
			respondErrorf(w, http.StatusNotImplemented, "'RefQuery' not yet implemented by 'EqOp'")

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
