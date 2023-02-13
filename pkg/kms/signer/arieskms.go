/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"strings"
	"time"

	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	noopMetricsProvider "github.com/trustbloc/vcs/pkg/observability/metrics/noop"
)

type metricsProvider interface {
	SignTime(value time.Duration)
}

// KMSSigner to crypto sign a message.
// Note: do not create an instance of KMSSigner directly. Use NewKMSSigner() instead.
type KMSSigner struct {
	keyHandle     interface{}
	crypto        crypto
	signatureType vcsverifiable.SignatureType
	bbs           bool
	metrics       metricsProvider
}

type keyManager interface {
	Get(keyID string) (interface{}, error)
}

type crypto interface {
	Sign(msg []byte, kh interface{}) ([]byte, error)
	SignMulti(messages [][]byte, kh interface{}) ([]byte, error)
}

func NewKMSSigner(keyManager keyManager, c crypto, kmsKeyID string,
	signatureType vcsverifiable.SignatureType, metrics metricsProvider) (*KMSSigner, error) {
	kh, err := keyManager.Get(kmsKeyID)
	if err != nil {
		return nil, err
	}

	if metrics == nil {
		metrics = &noopMetricsProvider.NoMetrics{}
	}

	return &KMSSigner{
		keyHandle: kh, crypto: c,
		signatureType: signatureType,
		bbs:           signatureType == vcsverifiable.BbsBlsSignature2020,
		metrics:       metrics,
	}, nil
}

func (s *KMSSigner) Sign(data []byte) ([]byte, error) {
	startTime := time.Now()

	defer func() {
		s.metrics.SignTime(time.Since(startTime))
	}()

	if s.bbs {
		return s.crypto.SignMulti(s.textToLines(string(data)), s.keyHandle)
	}

	v, err := s.crypto.Sign(data, s.keyHandle)
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
