package oidc4ci

import "github.com/trustbloc/vc-go/verifiable"

type DefaultLDPProofParser struct {
}

func NewDefaultLDPProofParser() *DefaultLDPProofParser {
	return &DefaultLDPProofParser{}
}

func (p *DefaultLDPProofParser) Parse(
	rawProof []byte,
	opt []verifiable.PresentationOpt,
) (*verifiable.Presentation, error) {
	return verifiable.ParsePresentation(rawProof,
		opt...,
	)
}
