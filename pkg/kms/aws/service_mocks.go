// Code generated by MockGen. DO NOT EDIT.
// Source: service.go

// Package aws is a generated GoMock package.
package aws

import (
	context "context"
	reflect "reflect"
	time "time"

	kms "github.com/aws/aws-sdk-go-v2/service/kms"
	gomock "github.com/golang/mock/gomock"
)

// MockawsClient is a mock of awsClient interface.
type MockawsClient struct {
	ctrl     *gomock.Controller
	recorder *MockawsClientMockRecorder
}

// MockawsClientMockRecorder is the mock recorder for MockawsClient.
type MockawsClientMockRecorder struct {
	mock *MockawsClient
}

// NewMockawsClient creates a new mock instance.
func NewMockawsClient(ctrl *gomock.Controller) *MockawsClient {
	mock := &MockawsClient{ctrl: ctrl}
	mock.recorder = &MockawsClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockawsClient) EXPECT() *MockawsClientMockRecorder {
	return m.recorder
}

// CreateAlias mocks base method.
func (m *MockawsClient) CreateAlias(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, params}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateAlias", varargs...)
	ret0, _ := ret[0].(*kms.CreateAliasOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAlias indicates an expected call of CreateAlias.
func (mr *MockawsClientMockRecorder) CreateAlias(ctx, params interface{}, optFns ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, params}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAlias", reflect.TypeOf((*MockawsClient)(nil).CreateAlias), varargs...)
}

// CreateKey mocks base method.
func (m *MockawsClient) CreateKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, params}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateKey", varargs...)
	ret0, _ := ret[0].(*kms.CreateKeyOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateKey indicates an expected call of CreateKey.
func (mr *MockawsClientMockRecorder) CreateKey(ctx, params interface{}, optFns ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, params}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateKey", reflect.TypeOf((*MockawsClient)(nil).CreateKey), varargs...)
}

// Decrypt mocks base method.
func (m *MockawsClient) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, params}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Decrypt", varargs...)
	ret0, _ := ret[0].(*kms.DecryptOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Decrypt indicates an expected call of Decrypt.
func (mr *MockawsClientMockRecorder) Decrypt(ctx, params interface{}, optFns ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, params}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Decrypt", reflect.TypeOf((*MockawsClient)(nil).Decrypt), varargs...)
}

// DescribeKey mocks base method.
func (m *MockawsClient) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, params}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DescribeKey", varargs...)
	ret0, _ := ret[0].(*kms.DescribeKeyOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DescribeKey indicates an expected call of DescribeKey.
func (mr *MockawsClientMockRecorder) DescribeKey(ctx, params interface{}, optFns ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, params}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DescribeKey", reflect.TypeOf((*MockawsClient)(nil).DescribeKey), varargs...)
}

// Encrypt mocks base method.
func (m *MockawsClient) Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, params}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Encrypt", varargs...)
	ret0, _ := ret[0].(*kms.EncryptOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Encrypt indicates an expected call of Encrypt.
func (mr *MockawsClientMockRecorder) Encrypt(ctx, params interface{}, optFns ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, params}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Encrypt", reflect.TypeOf((*MockawsClient)(nil).Encrypt), varargs...)
}

// GetPublicKey mocks base method.
func (m *MockawsClient) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, params}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetPublicKey", varargs...)
	ret0, _ := ret[0].(*kms.GetPublicKeyOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPublicKey indicates an expected call of GetPublicKey.
func (mr *MockawsClientMockRecorder) GetPublicKey(ctx, params interface{}, optFns ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, params}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPublicKey", reflect.TypeOf((*MockawsClient)(nil).GetPublicKey), varargs...)
}

// ScheduleKeyDeletion mocks base method.
func (m *MockawsClient) ScheduleKeyDeletion(ctx context.Context, params *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, params}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ScheduleKeyDeletion", varargs...)
	ret0, _ := ret[0].(*kms.ScheduleKeyDeletionOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ScheduleKeyDeletion indicates an expected call of ScheduleKeyDeletion.
func (mr *MockawsClientMockRecorder) ScheduleKeyDeletion(ctx, params interface{}, optFns ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, params}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ScheduleKeyDeletion", reflect.TypeOf((*MockawsClient)(nil).ScheduleKeyDeletion), varargs...)
}

// Sign mocks base method.
func (m *MockawsClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, params}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Sign", varargs...)
	ret0, _ := ret[0].(*kms.SignOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Sign indicates an expected call of Sign.
func (mr *MockawsClientMockRecorder) Sign(ctx, params interface{}, optFns ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, params}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sign", reflect.TypeOf((*MockawsClient)(nil).Sign), varargs...)
}

// Verify mocks base method.
func (m *MockawsClient) Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, params}
	for _, a := range optFns {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Verify", varargs...)
	ret0, _ := ret[0].(*kms.VerifyOutput)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Verify indicates an expected call of Verify.
func (mr *MockawsClientMockRecorder) Verify(ctx, params interface{}, optFns ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, params}, optFns...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockawsClient)(nil).Verify), varargs...)
}

// MockmetricsProvider is a mock of metricsProvider interface.
type MockmetricsProvider struct {
	ctrl     *gomock.Controller
	recorder *MockmetricsProviderMockRecorder
}

// MockmetricsProviderMockRecorder is the mock recorder for MockmetricsProvider.
type MockmetricsProviderMockRecorder struct {
	mock *MockmetricsProvider
}

// NewMockmetricsProvider creates a new mock instance.
func NewMockmetricsProvider(ctrl *gomock.Controller) *MockmetricsProvider {
	mock := &MockmetricsProvider{ctrl: ctrl}
	mock.recorder = &MockmetricsProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockmetricsProvider) EXPECT() *MockmetricsProviderMockRecorder {
	return m.recorder
}

// DecryptCount mocks base method.
func (m *MockmetricsProvider) DecryptCount() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DecryptCount")
}

// DecryptCount indicates an expected call of DecryptCount.
func (mr *MockmetricsProviderMockRecorder) DecryptCount() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptCount", reflect.TypeOf((*MockmetricsProvider)(nil).DecryptCount))
}

// DecryptTime mocks base method.
func (m *MockmetricsProvider) DecryptTime(value time.Duration) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DecryptTime", value)
}

// DecryptTime indicates an expected call of DecryptTime.
func (mr *MockmetricsProviderMockRecorder) DecryptTime(value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptTime", reflect.TypeOf((*MockmetricsProvider)(nil).DecryptTime), value)
}

// EncryptCount mocks base method.
func (m *MockmetricsProvider) EncryptCount() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "EncryptCount")
}

// EncryptCount indicates an expected call of EncryptCount.
func (mr *MockmetricsProviderMockRecorder) EncryptCount() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptCount", reflect.TypeOf((*MockmetricsProvider)(nil).EncryptCount))
}

// EncryptTime mocks base method.
func (m *MockmetricsProvider) EncryptTime(value time.Duration) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "EncryptTime", value)
}

// EncryptTime indicates an expected call of EncryptTime.
func (mr *MockmetricsProviderMockRecorder) EncryptTime(value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EncryptTime", reflect.TypeOf((*MockmetricsProvider)(nil).EncryptTime), value)
}

// ExportPublicKeyCount mocks base method.
func (m *MockmetricsProvider) ExportPublicKeyCount() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ExportPublicKeyCount")
}

// ExportPublicKeyCount indicates an expected call of ExportPublicKeyCount.
func (mr *MockmetricsProviderMockRecorder) ExportPublicKeyCount() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExportPublicKeyCount", reflect.TypeOf((*MockmetricsProvider)(nil).ExportPublicKeyCount))
}

// ExportPublicKeyTime mocks base method.
func (m *MockmetricsProvider) ExportPublicKeyTime(value time.Duration) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ExportPublicKeyTime", value)
}

// ExportPublicKeyTime indicates an expected call of ExportPublicKeyTime.
func (mr *MockmetricsProviderMockRecorder) ExportPublicKeyTime(value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExportPublicKeyTime", reflect.TypeOf((*MockmetricsProvider)(nil).ExportPublicKeyTime), value)
}

// SignCount mocks base method.
func (m *MockmetricsProvider) SignCount() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SignCount")
}

// SignCount indicates an expected call of SignCount.
func (mr *MockmetricsProviderMockRecorder) SignCount() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignCount", reflect.TypeOf((*MockmetricsProvider)(nil).SignCount))
}

// SignTime mocks base method.
func (m *MockmetricsProvider) SignTime(value time.Duration) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SignTime", value)
}

// SignTime indicates an expected call of SignTime.
func (mr *MockmetricsProviderMockRecorder) SignTime(value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignTime", reflect.TypeOf((*MockmetricsProvider)(nil).SignTime), value)
}

// VerifyCount mocks base method.
func (m *MockmetricsProvider) VerifyCount() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "VerifyCount")
}

// VerifyCount indicates an expected call of VerifyCount.
func (mr *MockmetricsProviderMockRecorder) VerifyCount() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyCount", reflect.TypeOf((*MockmetricsProvider)(nil).VerifyCount))
}

// VerifyTime mocks base method.
func (m *MockmetricsProvider) VerifyTime(value time.Duration) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "VerifyTime", value)
}

// VerifyTime indicates an expected call of VerifyTime.
func (mr *MockmetricsProviderMockRecorder) VerifyTime(value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyTime", reflect.TypeOf((*MockmetricsProvider)(nil).VerifyTime), value)
}
