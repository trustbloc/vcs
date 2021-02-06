package zcapld

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

type DIDResolver interface {
	Accept(method string) bool
	Read(did string, options ...vdr.ResolveOption) (*did.DocResolution, error)
}

type KMS interface {
	Get(kid string) (interface{}, error)
	PubKeyBytesToHandle([]byte, kms.KeyType) (interface{}, error)
}

type Crypto interface {
	Sign(msg []byte, kh interface{}) ([]byte, error)
	Verify(sig, msg []byte, kh interface{}) error
}
