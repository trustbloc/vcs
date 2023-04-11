# MongoDB Storage Implementation for Fosite
This document describes the implementation of MongoDB storage for Fosite, an open-source OAuth2 and OpenID Connect framework written in the Go programming language.

## Overview
Fosite provides an in-memory storage backend by default, which is suitable for small-scale applications. However, for large-scale applications that require persistent storage, it's recommended to use a database such as MongoDB.

The MongoDB storage implementation for Fosite is based on the fosite.Store interface, which defines the methods for storing and retrieving OAuth2 and OIDC entities such as clients, tokens, and authorizations.

## Configuration
To use MongoDB storage with Fosite, you need to create a new instance of Store as described [here](https://github.com/trustbloc/vcs/blob/main/cmd/vc-rest/startcmd/oauth_provider.go#L25).

## Implementation Details
The MongoDB storage implementation for Fosite uses the `go.mongodb.org/mongo-driver/mongo` package, which provides a MongoDB driver for Go.

The implementation consists of the following types and methods:

`Store` is the main type that implements:
- `fosite.Store`
- `oauth2.CoreStorage`
- `oauth2.TokenRevocationStorage`
- `pkce.PKCERequestStorage`
- `fosite.PARStorage`

We store following collections in mongodb:
- `fosite_clients`: stores OAuth2 client information.
- `fosite_par`: stores PAR (Pushed Authorization Request) tokens. Default data expiration is 24h.
- `fosite_auth_code`: stores authorization code sessions. Default data expiration is 24h.
- `fosite_pkce_sessions`: stores PKCE (Proof Key for Code Exchange) sessions. Default data expiration is 24h.
- `fosite_refresh_token_sessions`: stores refresh token sessions. Default data expiration is 24h.
- `fosite_access_token_sessions`: stores access token sessions.
- `fosite_blacklisted_jtis`: stores JWT ID (JTI) claims that have been blacklisted. Default data expiration is 24h.

## Collections
### fosite_clients
The `fosite_clients` collection stores instances of the `Client` struct, which implements the `fosite.Client` interface. The Client struct has the following fields:
Client entity represents an application or service that is registered with the authorization server and is authorized to access protected resources on behalf of a user

- ID: a unique identifier for the client.
- Secret: a hashed representation of the client's secret.
- RotatedSecrets: a list of previously used secrets, hashed and stored in chronological order.
- RedirectURIs: a list of URIs to which the authorization server will redirect the user after granting or denying access.
- GrantTypes: a list of grant types that the client is authorized to use.
- ResponseTypes: a list of response types that the client is authorized to use.
- Scopes: a list of scopes that the client is authorized to request.
- Audience: a list of audiences that the client is authorized to request.
- Public: a boolean value that indicates whether the client is a public client (e.g., a mobile app or a single-page web app).

### fosite_par
The `fosite_par` collection stores instances of the authorizeRequest struct, which represents a pushed authorization request (PAR) that has been authorized by the user.
PAR (Pushed Authorization Requests) is a feature introduced in the OAuth 2.0 Pushed Authorization Requests (PAR) draft specification. It allows a client to initiate an authorization request by sending it to the authorization server in a separate API call, rather than including it in the redirect URI used to initiate the authorization flow

The `par` struct has the following fields:
- ResponseTypes: a list of response types requested by the client.
- RedirectURI: the URI to which the authorization server will redirect the user after granting or denying access.
- State: an opaque value that the client can use to maintain state between the authorization request and the callback.
- HandledResponseTypes: a list of response types that the authorization server is capable of handling.
- ResponseMode: the response mode requested by the client.
- DefaultResponseMode: the default response mode to use if the client does not request a specific response mode.
- ClientID: the unique identifier of the client that requested the authorization.

### fosite_auth_code
The `fosite_auth_code` collection stores instances of the request struct, which represents an authorization request that has been granted.
Authorization code is a temporary code that is issued by the authorization server to the client application after the user grants authorization. This authorization code is then exchanged by the client for an access token that allows the client to access the protected resources on behalf of the user.


The struct has the following fields:
- ID: the unique identifier of the authorization request.
- RequestedAt: the time when the authorization request was made.
- RequestedScope: a list of scopes requested by the client.
- GrantedScope: a list of scopes granted by the authorization server.
- Form: the form data submitted with the authorization request.
- RequestedAudience: a list of audiences requested by the client.
- GrantedAudience: a list of audiences granted by the authorization server.
- Lang: the language tag of the preferred user interface language for the authorization server.
- ClientID: the unique identifier of the client that requested the authorization.
- SessionExtra: additional data that can be stored with the authorization request.

### fosite_pkce_sessions
The `fosite_pkce_sessions` collection stores instances of the `session` struct, which represents a PKCE (Proof Key for Code Exchange) session.
PKCE is an extension to the OAuth2 authorization code flow that aims to prevent authorization code interception attacks. It allows a client to provide a code verifier when requesting an authorization code, and later provide the same code verifier when exchanging the authorization code for an access token. This allows the authorization server to verify that the client that is exchanging the authorization code is the same client that originally requested it.

The `session` struct has the following fields:
- ID: the unique identifier of the PKCE session.
- RequestedAt: the time when the PKCE session was requested.
- RequestedScope: a list of scopes requested by the client.
- GrantedScope: a list of scopes granted by the authorization server.
- Form: the form data submitted with the PKCE session request.
- RequestedAudience: a list of audiences requested by the client.
- GrantedAudience: a list of audiences granted by the authorization server.
- Lang: the language tag of the preferred user interface language for the authorization server.
- ClientID: the unique identifier of the client that requested the PKCE session.
- SessionExtra: additional data that can be stored with the PKCE session.

### fosite_refresh_token_sessions
The fosite_refresh_token_sessions collection in Fosite stores refresh token session data. 
A refresh token is a special type of token that is used to obtain a new access token when the current access token has expired

The `session` struct has the following fields:
- ID: the unique identifier of the PKCE session.
- RequestedAt: the time when the PKCE session was requested.
- RequestedScope: a list of scopes requested by the client.
- GrantedScope: a list of scopes granted by the authorization server.
- Form: the form data submitted with the PKCE session request.
- RequestedAudience: a list of audiences requested by the client.
- GrantedAudience: a list of audiences granted by the authorization server.
- Lang: the language tag of the preferred user interface language for the authorization server.
- ClientID: the unique identifier of the client that requested the PKCE session.
- SessionExtra: additional data that can be stored with the PKCE session.

### fosite_access_token_sessions
The `fosite_access_token_sessions` collection in MongoDB stores access token sessions.
An access token is a credential that a client uses to access protected resources on behalf of a user. When a client is granted an access token, it is stored in the fosite_access_token_sessions collection along with associated data.

The `session` struct has the following fields:
- ID: the unique identifier of the PKCE session.
- RequestedAt: the time when the PKCE session was requested.
- RequestedScope: a list of scopes requested by the client.
- GrantedScope: a list of scopes granted by the authorization server.
- Form: the form data submitted with the PKCE session request.
- RequestedAudience: a list of audiences requested by the client.
- GrantedAudience: a list of audiences granted by the authorization server.
- Lang: the language tag of the preferred user interface language for the authorization server.
- ClientID: the unique identifier of the client that requested the PKCE session.
- SessionExtra: additional data that can be stored with the PKCE session.

### fosite_blacklisted_jtis
The `fosite_blacklisted_jtis` is a collection that stores JWT (JSON Web Token) IDs that have been invalidated by the authorization server. JWTs are often used for access tokens and they contain information about the user or client that is authorized to access a protected resource.
When a JWT is invalidated, it means that it is no longer valid and cannot be used to access protected resources. This can happen for various reasons, such as when the user revokes their consent or when the token has expired.


## Flow
Here is an example of how the Authorization Code flow with PAR (Proof of Authorized Request) and PKCE (Proof Key for Code Exchange) can use the different collections in Fosite:

1. The client initiates the Authorization Code flow by redirecting the user to the authorization endpoint with the necessary parameters, including a PKCE code challenge and method. The authorization endpoint is responsible for creating an authorization code and storing it in the `fosite_auth_code` collection along with the request details, such as the client ID, requested scopes, and PKCE session data in the `fosite_pkce_sessions` collection.
2. After the user grants authorization, the authorization endpoint creates a PAR (Proof of Authorized Request) and returns it to the client. The PAR is stored in the `fosite_par` collection along with the request details, such as the client ID, response types, redirect URI, and scopes.
3. The client then exchanges the PAR for an access token by making a request to the token endpoint with the PAR, PKCE code verifier, and client credentials. The token endpoint validates the PAR, PKCE, and client credentials and retrieves the stored request details from the `fosite_par` and `fosite_pkce_sessions` collections. If everything checks out, the token endpoint generates an access token and stores it in the `fosite_access_token_sessions` collection along with the request details, such as the client ID, scopes, and audience. The token endpoint also generates a refresh token and stores it in the `fosite_refresh_token_sessions` collection along with the request details, such as the client ID, scopes, and audience.
4. The client can then use the access token to access protected resources by including it in the authorization header of its requests. The resource server extracts the access token from the authorization header and validates it by retrieving the stored request details from the `fosite_access_token_sessions` collection.
5. If the access token has expired, the client can use the refresh token to obtain a new access token. The client makes a request to the token endpoint with the refresh token and client credentials. The token endpoint retrieves the stored request details from the `fosite_refresh_token_sessions` collection, validates the client credentials, and generates a new access token, which is stored in the `fosite_access_token_sessions` collection. The token endpoint also generates a new refresh token and stores it in the `fosite_refresh_token_sessions` collection.
6.  If the client revokes the refresh token, the authorization server adds the refresh token's ID to the `fosite_blacklisted_jtis collection` to prevent it from being used again.

Overall, the `fosite_auth_code`, `fosite_pkce_sessions`, `fosite_par`, `fosite_access_token_sessions`, `fosite_blacklisted_jtis` and `fosite_refresh_token_sessions` collections are used to store and retrieve request details and tokens during the Authorization Code flow with PAR and PKCE.