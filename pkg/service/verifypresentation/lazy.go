/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifypresentation

import (
	"encoding/json"
	"sync"
)

type LazyCredential struct {
	raw        interface{}
	serialized []byte
	mut        sync.Mutex
}

func NewLazyCredential(raw interface{}) *LazyCredential {
	return &LazyCredential{
		raw: raw,
		mut: sync.Mutex{},
	}
}

func (l *LazyCredential) Serialized() ([]byte, error) {
	l.mut.Lock()
	defer l.mut.Unlock()
	if l.serialized != nil {
		return l.serialized, nil
	}

	vcBytes, err := json.Marshal(l.raw)
	if err != nil {
		return nil, err
	}

	l.serialized = vcBytes
	return vcBytes, nil
}

func (l *LazyCredential) Raw() interface{} {
	return l.raw
}
