/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"errors"
	"strings"
	"time"

	"github.com/trustbloc/kms-go/wrapper/api"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	noopMetricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics/noop"
)

type metricsProvider interface {
	SignTime(value time.Duration)
}

// KMSSigner to crypto sign a message.
// Note: do not create an instance of KMSSigner directly. Use NewKMSSigner() instead.
type KMSSigner struct {
	signatureType vcsverifiable.SignatureType
	bbs           bool
	metrics       metricsProvider
	signer        api.FixedKeySigner
	multiSigner   api.FixedKeyMultiSigner
}

func NewKMSSigner(multiSigner api.FixedKeySigner,
	signatureType vcsverifiable.SignatureType, metrics metricsProvider) *KMSSigner {
	if metrics == nil {
		metrics = &noopMetricsProvider.NoMetrics{}
	}

	return &KMSSigner{
		signatureType: signatureType,
		bbs:           signatureType == vcsverifiable.BbsBlsSignature2020,
		metrics:       metrics,
		signer:        multiSigner,
	}
}

func NewKMSSignerBBS(multiSigner api.FixedKeyMultiSigner,
	signatureType vcsverifiable.SignatureType, metrics metricsProvider) *KMSSigner {
	if metrics == nil {
		metrics = &noopMetricsProvider.NoMetrics{}
	}

	return &KMSSigner{
		signatureType: signatureType,
		bbs:           signatureType == vcsverifiable.BbsBlsSignature2020,
		metrics:       metrics,
		signer:        multiSigner,
		multiSigner:   multiSigner,
	}
}

func (s *KMSSigner) Sign(data []byte) ([]byte, error) {
	startTime := time.Now()

	defer func() {
		s.metrics.SignTime(time.Since(startTime))
	}()

	if s.bbs {
		if s.multiSigner == nil {
			return nil, errors.New("signer was not initialized with BBS support")
		}

		return s.multiSigner.SignMulti(s.textToLines(string(data)))
	}

	v, err := s.signer.Sign(data)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func (s *KMSSigner) Alg() string {
	return s.signatureType.Name()
}

func (s *KMSSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}
