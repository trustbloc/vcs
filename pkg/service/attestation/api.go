/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package attestation

import "context"

// ServiceInterface defines an interface for Attestation Service. The task of Attestation Service is to validate and
// confirm the device binding and authentication of the wallet instance.
type ServiceInterface interface {
	ValidateClientAttestationJWT(ctx context.Context, clientID, clientAttestationJWT string) error
	ValidateClientAttestationPoPJWT(ctx context.Context, clientID, clientAttestationPoPJWT string) error
	ValidateClientAttestationVP(ctx context.Context, clientID, jwtVP string) error
}
