/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	jsonld "github.com/piprate/json-gold/ld"
	ldcontext "github.com/trustbloc/did-go/doc/ld/context"
	ldstore "github.com/trustbloc/did-go/doc/ld/store"
	"github.com/trustbloc/kms-go/spi/storage"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
)

const (
	contextCollectionName = "ldcontext"
	contextURLFieldName   = "contextURL"
)

var _ ldstore.ContextStore = (*ContextStore)(nil)

type bsonRemoteDocument struct {
	DocumentURL string                 `bson:"documentURL,omitempty"`
	Document    map[string]interface{} `bson:"document"`
	ContextURL  string                 `bson:"contextURL"`
}

// ContextStore is mongodb implementation of JSON-LD context repository.
type ContextStore struct {
	mongoClient *mongodb.Client
}

// NewContextStore returns a new instance of ContextStore.
func NewContextStore(mongoClient *mongodb.Client) (*ContextStore, error) {
	s := &ContextStore{
		mongoClient: mongoClient,
	}

	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return s, nil
}

func (s *ContextStore) migrate() error {
	collection := s.mongoClient.Database().Collection(contextCollectionName)

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	if _, err := collection.Indexes().
		CreateOne(ctxWithTimeout,
			mongo.IndexModel{
				Keys: bson.D{
					{
						Key:   contextURLFieldName,
						Value: 1,
					},
				},
				Options: options.Index().SetUnique(true),
			},
		); err != nil {
		return err
	}

	return nil
}

// Get returns JSON-LD remote document from DB by context URL.
func (s *ContextStore) Get(u string) (*jsonld.RemoteDocument, error) {
	collection := s.mongoClient.Database().Collection(contextCollectionName)

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	var bsonDoc bsonRemoteDocument

	if err := collection.FindOne(ctxWithTimeout,
		bson.D{
			{
				Key:   contextURLFieldName,
				Value: u,
			},
		},
	).Decode(&bsonDoc); err != nil {
		if strings.Contains(err.Error(), "no documents in result") {
			return nil, storage.ErrDataNotFound
		}
		return nil, fmt.Errorf("find document: %w", err)
	}

	rd, err := mapToJSONLDRemoteDocument(&bsonDoc)
	if err != nil {
		return nil, fmt.Errorf("map from bson: %w", err)
	}

	return rd, nil
}

// Put saves JSON-LD remote document into DB.
func (s *ContextStore) Put(u string, rd *jsonld.RemoteDocument) error {
	collection := s.mongoClient.Database().Collection(contextCollectionName)

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	rd.ContextURL = u

	bsonDoc, err := mapToBSONRemoteDocument(rd)
	if err != nil {
		return fmt.Errorf("map to bson: %w", err)
	}

	if _, err = collection.InsertOne(ctxWithTimeout, bsonDoc); err != nil {
		return fmt.Errorf("insert document: %w", err)
	}

	return nil
}

// Import imports JSON-LD contexts into DB.
func (s *ContextStore) Import(documents []ldcontext.Document) error {
	hashes, er := s.computeHashesForContextsInDB()
	if er != nil {
		return fmt.Errorf("compute context hashes: %w", er)
	}

	var documentsToImport []ldcontext.Document

	for _, d := range documents {
		b, err := getJSONLDRemoteDocumentBytes(d)
		if err != nil {
			return fmt.Errorf("get remote document bytes: %w", err)
		}

		// filter out up-to-date contexts
		if computeHash(b) == hashes[d.URL] {
			continue
		}

		documentsToImport = append(documentsToImport, d)
	}

	if len(documentsToImport) == 0 {
		return nil
	}

	var bsonDocs []interface{}

	for _, d := range documentsToImport {
		content, err := jsonld.DocumentFromReader(bytes.NewReader(d.Content))
		if err != nil {
			return fmt.Errorf("document from reader: %w", err)
		}

		rd := &jsonld.RemoteDocument{
			DocumentURL: d.DocumentURL,
			Document:    content,
			ContextURL:  d.URL,
		}

		bsonDoc, err := mapToBSONRemoteDocument(rd)
		if err != nil {
			return fmt.Errorf("map to bson: %w", err)
		}

		bsonDocs = append(bsonDocs, bsonDoc)
	}

	collection := s.mongoClient.Database().Collection(contextCollectionName)

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	if _, err := collection.InsertMany(ctxWithTimeout, bsonDocs); err != nil {
		return fmt.Errorf("insert documents: %w", err)
	}

	return nil
}

// Delete deletes matched context documents in the underlying storage.
// Documents are matched by context URL and ld.RemoteDocument content hash.
func (s *ContextStore) Delete(documents []ldcontext.Document) error {
	hashes, computeErr := s.computeHashesForContextsInDB()
	if computeErr != nil {
		return fmt.Errorf("compute context hashes: %w", computeErr)
	}

	collection := s.mongoClient.Database().Collection(contextCollectionName)

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	for _, d := range documents {
		b, err := getJSONLDRemoteDocumentBytes(d)
		if err != nil {
			return fmt.Errorf("get remote document bytes: %w", err)
		}

		// delete document only if content hashes match
		if computeHash(b) == hashes[d.URL] {
			if _, err = collection.DeleteOne(ctxWithTimeout,
				bson.D{
					{
						Key:   contextURLFieldName,
						Value: d.URL,
					},
				},
			); err != nil {
				return fmt.Errorf("delete context document: %w", err)
			}
		}
	}

	return nil
}

func (s *ContextStore) computeHashesForContextsInDB() (map[string]string, error) {
	collection := s.mongoClient.Database().Collection(contextCollectionName)

	ctxWithTimeout, cancel := s.mongoClient.ContextWithTimeout()
	defer cancel()

	cursor, findErr := collection.Find(ctxWithTimeout, bson.D{})
	if findErr != nil {
		return nil, fmt.Errorf("find documents: %w", findErr)
	}

	defer cursor.Close(ctxWithTimeout) //nolint:errcheck

	var bsonDocs []bsonRemoteDocument

	if err := cursor.All(ctxWithTimeout, &bsonDocs); err != nil {
		return nil, fmt.Errorf("get all documents: %w", err)
	}

	hashes := make(map[string]string)

	for _, bsonDoc := range bsonDocs {
		doc := bsonDoc // to avoid memory aliasing in the loop

		rd, err := mapToJSONLDRemoteDocument(&doc)
		if err != nil {
			return nil, fmt.Errorf("map to remote document: %w", err)
		}

		b, err := json.Marshal(rd)
		if err != nil {
			return nil, fmt.Errorf("marshal document: %w", err)
		}

		hashes[rd.ContextURL] = computeHash(b)
	}

	return hashes, nil
}

func computeHash(b []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func getJSONLDRemoteDocumentBytes(d ldcontext.Document) ([]byte, error) {
	content, err := jsonld.DocumentFromReader(bytes.NewReader(d.Content))
	if err != nil {
		return nil, fmt.Errorf("document from reader: %w", err)
	}

	rd := &jsonld.RemoteDocument{
		DocumentURL: d.DocumentURL,
		Document:    content,
		ContextURL:  d.URL,
	}

	b, err := json.Marshal(rd)
	if err != nil {
		return nil, fmt.Errorf("marshal remote document: %w", err)
	}

	return b, nil
}

func mapToBSONRemoteDocument(rd *jsonld.RemoteDocument) (*bsonRemoteDocument, error) {
	content, err := mongodb.StructureToMap(rd.Document)
	if err != nil {
		return nil, err
	}

	return &bsonRemoteDocument{
		DocumentURL: rd.DocumentURL,
		Document:    content,
		ContextURL:  rd.ContextURL,
	}, nil
}

func mapToJSONLDRemoteDocument(doc *bsonRemoteDocument) (*jsonld.RemoteDocument, error) {
	var content interface{}

	if err := mongodb.MapToStructure(doc.Document, &content); err != nil {
		return nil, err
	}

	return &jsonld.RemoteDocument{
		DocumentURL: doc.DocumentURL,
		Document:    content,
		ContextURL:  doc.ContextURL,
	}, nil
}
