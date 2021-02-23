/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"
	"github.com/go-openapi/runtime"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edv/pkg/restapi/models"

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

	var prevDoc interface{}

	for i := range op.Args() {
		query := op.Args()[i]

		var document interface{}

		switch q := query.(type) {
		case *openapi.DocQuery:
			var err error

			document, err = o.fetchDocument(q)
			if err != nil {
				respondErrorf(w, http.StatusInternalServerError,
					"failed to fetch Confidential Storage document for docquery: %s", err.Error())

				return
			}
		case *openapi.RefQuery:
			var proceed bool

			document, proceed = o.resolveRefQuery(w, q)
			if !proceed {
				return
			}
		}

		if i == 0 {
			prevDoc = document

			continue
		}

		comparison.Result = reflect.DeepEqual(prevDoc, document)
		if !comparison.Result {
			break
		}

		prevDoc = document
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	respond(w, http.StatusOK, headers, comparison)
}

func (o *Operation) fetchDocument(query openapi.Query) (interface{}, error) {
	docQuery, ok := query.(*openapi.DocQuery)
	if !ok {
		return nil, fmt.Errorf("cannot fetch structured documents for query type: %s", query.Type())
	}

	contents, err := o.ReadDocQuery(docQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to read Confidential Storage document: %w", err)
	}

	document := &models.StructuredDocument{}

	err = json.Unmarshal(contents, document)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Confidential Storage structured document: %w", err)
	}

	var result interface{} = document.Content

	if docQuery.Path != "" {
		builder := gval.Full(jsonpath.PlaceholderExtension())

		path, err := builder.NewEvaluable(docQuery.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to build new json path evaluator: %w", err)
		}

		result, err = path(context.TODO(), result)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate json path [%s]: %w", docQuery.Path, err)
		}
	}

	return result, nil
}

func (o *Operation) resolveRefQuery(w http.ResponseWriter, query *openapi.RefQuery) (interface{}, bool) {
	raw, err := o.storage.queries.Get(*query.Ref)
	if errors.Is(err, storage.ErrValueNotFound) {
		respondErrorf(w, http.StatusBadRequest, "no such query: %s", *query.Ref)

		return nil, false
	}

	if err != nil {
		respondErrorf(w, http.StatusInternalServerError,
			"failed to fetch query object for ref %s: %s", *query.Ref, err.Error())

		return nil, false
	}

	savedQuery := &Query{}

	err = json.NewDecoder(bytes.NewReader(raw)).Decode(savedQuery)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError, "failed to parse doc query: %s", err)

		return nil, false
	}

	querySpec, err := openapi.UnmarshalQuery(bytes.NewReader(savedQuery.Spec), runtime.JSONConsumer())
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError, "failed to parse query spec: %s", err.Error())

		return nil, false
	}

	document, err := o.fetchDocument(querySpec)
	if err != nil {
		respondErrorf(w, http.StatusInternalServerError,
			"failed to fetch Confidential Storage document for refquery: %s", err.Error())

		return nil, false
	}

	return document, true
}
