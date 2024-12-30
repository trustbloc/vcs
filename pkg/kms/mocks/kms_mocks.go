// Code generated by MockGen. DO NOT EDIT.
// Source: kms.go

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	jwk "github.com/trustbloc/kms-go/doc/jose/jwk"
	kms "github.com/trustbloc/kms-go/spi/kms"
	vc "github.com/trustbloc/vcs/pkg/doc/vc"
	verifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

// MockVCSKeyManager is a mock of VCSKeyManager interface.
type MockVCSKeyManager struct {
	ctrl     *gomock.Controller
	recorder *MockVCSKeyManagerMockRecorder
}

// MockVCSKeyManagerMockRecorder is the mock recorder for MockVCSKeyManager.
type MockVCSKeyManagerMockRecorder struct {
	mock *MockVCSKeyManager
}

// NewMockVCSKeyManager creates a new mock instance.
func NewMockVCSKeyManager(ctrl *gomock.Controller) *MockVCSKeyManager {
	mock := &MockVCSKeyManager{ctrl: ctrl}
	mock.recorder = &MockVCSKeyManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVCSKeyManager) EXPECT() *MockVCSKeyManagerMockRecorder {
	return m.recorder
}

// CreateCryptoKey mocks base method.
func (m *MockVCSKeyManager) CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateCryptoKey", keyType)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(interface{})
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CreateCryptoKey indicates an expected call of CreateCryptoKey.
func (mr *MockVCSKeyManagerMockRecorder) CreateCryptoKey(keyType interface{}) *VCSKeyManagerCreateCryptoKeyCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateCryptoKey", reflect.TypeOf((*MockVCSKeyManager)(nil).CreateCryptoKey), keyType)
	return &VCSKeyManagerCreateCryptoKeyCall{Call: call}
}

// VCSKeyManagerCreateCryptoKeyCall wrap *gomock.Call
type VCSKeyManagerCreateCryptoKeyCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *VCSKeyManagerCreateCryptoKeyCall) Return(arg0 string, arg1 interface{}, arg2 error) *VCSKeyManagerCreateCryptoKeyCall {
	c.Call = c.Call.Return(arg0, arg1, arg2)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *VCSKeyManagerCreateCryptoKeyCall) Do(f func(kms.KeyType) (string, interface{}, error)) *VCSKeyManagerCreateCryptoKeyCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *VCSKeyManagerCreateCryptoKeyCall) DoAndReturn(f func(kms.KeyType) (string, interface{}, error)) *VCSKeyManagerCreateCryptoKeyCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// CreateJWKKey mocks base method.
func (m *MockVCSKeyManager) CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateJWKKey", keyType)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(*jwk.JWK)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CreateJWKKey indicates an expected call of CreateJWKKey.
func (mr *MockVCSKeyManagerMockRecorder) CreateJWKKey(keyType interface{}) *VCSKeyManagerCreateJWKKeyCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateJWKKey", reflect.TypeOf((*MockVCSKeyManager)(nil).CreateJWKKey), keyType)
	return &VCSKeyManagerCreateJWKKeyCall{Call: call}
}

// VCSKeyManagerCreateJWKKeyCall wrap *gomock.Call
type VCSKeyManagerCreateJWKKeyCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *VCSKeyManagerCreateJWKKeyCall) Return(arg0 string, arg1 *jwk.JWK, arg2 error) *VCSKeyManagerCreateJWKKeyCall {
	c.Call = c.Call.Return(arg0, arg1, arg2)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *VCSKeyManagerCreateJWKKeyCall) Do(f func(kms.KeyType) (string, *jwk.JWK, error)) *VCSKeyManagerCreateJWKKeyCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *VCSKeyManagerCreateJWKKeyCall) DoAndReturn(f func(kms.KeyType) (string, *jwk.JWK, error)) *VCSKeyManagerCreateJWKKeyCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// NewVCSigner mocks base method.
func (m *MockVCSKeyManager) NewVCSigner(creator string, signatureType verifiable.SignatureType) (vc.SignerAlgorithm, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewVCSigner", creator, signatureType)
	ret0, _ := ret[0].(vc.SignerAlgorithm)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewVCSigner indicates an expected call of NewVCSigner.
func (mr *MockVCSKeyManagerMockRecorder) NewVCSigner(creator, signatureType interface{}) *VCSKeyManagerNewVCSignerCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewVCSigner", reflect.TypeOf((*MockVCSKeyManager)(nil).NewVCSigner), creator, signatureType)
	return &VCSKeyManagerNewVCSignerCall{Call: call}
}

// VCSKeyManagerNewVCSignerCall wrap *gomock.Call
type VCSKeyManagerNewVCSignerCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *VCSKeyManagerNewVCSignerCall) Return(arg0 vc.SignerAlgorithm, arg1 error) *VCSKeyManagerNewVCSignerCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *VCSKeyManagerNewVCSignerCall) Do(f func(string, verifiable.SignatureType) (vc.SignerAlgorithm, error)) *VCSKeyManagerNewVCSignerCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *VCSKeyManagerNewVCSignerCall) DoAndReturn(f func(string, verifiable.SignatureType) (vc.SignerAlgorithm, error)) *VCSKeyManagerNewVCSignerCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SupportedKeyTypes mocks base method.
func (m *MockVCSKeyManager) SupportedKeyTypes() []kms.KeyType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SupportedKeyTypes")
	ret0, _ := ret[0].([]kms.KeyType)
	return ret0
}

// SupportedKeyTypes indicates an expected call of SupportedKeyTypes.
func (mr *MockVCSKeyManagerMockRecorder) SupportedKeyTypes() *VCSKeyManagerSupportedKeyTypesCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SupportedKeyTypes", reflect.TypeOf((*MockVCSKeyManager)(nil).SupportedKeyTypes))
	return &VCSKeyManagerSupportedKeyTypesCall{Call: call}
}

// VCSKeyManagerSupportedKeyTypesCall wrap *gomock.Call
type VCSKeyManagerSupportedKeyTypesCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *VCSKeyManagerSupportedKeyTypesCall) Return(arg0 []kms.KeyType) *VCSKeyManagerSupportedKeyTypesCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *VCSKeyManagerSupportedKeyTypesCall) Do(f func() []kms.KeyType) *VCSKeyManagerSupportedKeyTypesCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *VCSKeyManagerSupportedKeyTypesCall) DoAndReturn(f func() []kms.KeyType) *VCSKeyManagerSupportedKeyTypesCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
