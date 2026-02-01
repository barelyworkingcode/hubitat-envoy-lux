# OAuth Flow Analysis for Enphase Authentication

## Flow Overview
The Enphase authentication uses OAuth 2.0 with PKCE (Proof Key for Code Exchange), which is designed for security in environments where the client secret cannot be securely stored.

## URL Parameters Analysis
From the example URL: `https://entrez.enphaseenergy.com/authorize?code_challenge=<< generated >>&client_id=envoy-ui-client&redirect_uri=https://envoy.lan/auth/callback&scope=<< serial number >>&response_type=code&code_challenge_method=S256`

- **code_challenge**: Base64URL-encoded SHA256 hash of the code_verifier
- **code_challenge_method**: S256 (SHA256 hash method)
- **client_id**: envoy-ui-client (fixed)
- **redirect_uri**: https://envoy.lan/auth/callback (fixed)
- **scope**: device serial number (appears to be a numeric scope identifier)
- **response_type**: code (authorization code flow)

## PKCE Process
1. **Generate code_verifier**: Random 43-128 character string (URL-safe)
2. **Generate code_challenge**: Base64URL(SHA256(code_verifier))
3. **Authorization Request**: Send user to authorization server with code_challenge
4. **Authorization Code**: Server redirects back with authorization code
5. **Token Exchange**: Exchange code + code_verifier for access token

## Implementation Options for Groovy

### Option 1: Generate our own PKCE parameters
- Generate random code_verifier
- Calculate SHA256 hash and Base64URL encode for code_challenge
- Construct authorization URL
- Handle callback and extract authorization code
- Exchange code for session token

### Option 2: Scrape existing parameters
- Visit envoy.lan
- Extract the generated code_challenge from the authorization URL
- Use those parameters for authentication

## Security Considerations
- code_verifier must be cryptographically random
- code_verifier should be 43-128 characters long
- Use Base64URL encoding (not standard Base64)
- Each authentication session should use new PKCE parameters