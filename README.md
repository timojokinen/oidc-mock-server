# OIDC Mock Server

A lightweight mock server for simulating OpenID Connect (OIDC) providers. Designed for **development and testing purposes only**.

> ⚠️ **Warning**: This server is **NOT intended for production use**. It lacks security features required for production OIDC providers (client authentication, token revocation, redirect URI validation, etc.). Use only in development, testing, or CI/CD environments.

## Table of Contents

- [What's Supported](#whats-supported)
- [What's NOT Implemented](#whats-not-implemented)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Local Development](#local-development)

## What's Supported

### OIDC Features

- ✅ **Authorization Code Flow with PKCE** (`S256` and `plain` challenge methods)
- ✅ RS256 signed JWT tokens (ID token and access token)
- ✅ Configurable users, claims, and scopes
- ✅ Configurable token expiration
- ✅ Nonce support for replay protection
- ✅ Cookie-based session tracking
- ✅ RP-Initiated Logout with `post_logout_redirect_uri` and `id_token_hint` support
- ✅ Auto-generated or custom RSA key pairs

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `/.well-known/openid-configuration` | OpenID Connect Discovery document |
| `/oauth/authorize` | Authorization endpoint (displays login form) |
| `/oauth/token` | Token endpoint |
| `/userinfo` | UserInfo endpoint |
| `/token_keys` | JWKS endpoint |
| `/logout` | RP-Initiated Logout (GET and POST) |
| `/users` | Lists configured users (development helper) |

## What's NOT Implemented

- ❌ Implicit, Client Credentials, Password, Hybrid, and Refresh Token flows
- ❌ Client authentication (client secrets are not validated)
- ❌ Token signature verification, revocation, or introspection
- ❌ Redirect URI validation
- ❌ Dynamic client registration
- ❌ Encrypted tokens (JWE) or multiple signing algorithms

## Installation

### As an npm Package

```bash
npm install @timojokinen/oidc-mock-server
```

```typescript
import express from 'express';
import { oidcMockServerMiddleware } from '@timojokinen/oidc-mock-server';

const app = express();

app.use(oidcMockServerMiddleware({
  issuer: 'http://localhost:3000',
  users: [
    { sub: 'user1', name: 'John Doe', email: 'john@example.com' },
  ],
  scopes: {
    profile: ['name'],
    email: ['email'],
  },
}));

app.listen(3000);
```

### Using Docker

```bash
# Pull and run with default configuration
docker pull timojokinen/oidc-mock-server:latest
docker run -p 3000:3000 timojokinen/oidc-mock-server:latest

# Run with custom configuration
docker run -p 3000:3000 \
  -v $(pwd)/my-config.json:/workspace/config.json \
  timojokinen/oidc-mock-server:latest

# Run with custom host/port
docker run -p 8080:8080 \
  -e PORT=8080 \
  -e HOST=http://my-oidc-server \
  timojokinen/oidc-mock-server:latest
```

#### Docker Compose Example

```yaml
version: '3.8'

services:
  oidc-mock:
    image: timojokinen/oidc-mock-server:latest
    ports:
      - "3000:3000"
    volumes:
      - ./oidc-config.json:/workspace/config.json
    environment:
      - PORT=3000
      - HOST=http://localhost

  my-app:
    build: .
    depends_on:
      - oidc-mock
    environment:
      - OIDC_ISSUER=http://oidc-mock:3000
```

## Configuration

### Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `issuer` | `string` | Yes | - | Issuer URL (must be valid URL) |
| `users` | `User[]` | Yes | - | Array of users (each must have `sub` field) |
| `baseClaims` | `object` | No | `{}` | Claims included for all users |
| `scopes` | `object` | No | `{}` | Maps scope names to claim arrays |
| `tokenExpiration` | `number` | No | `3600` | Token expiration in seconds |
| `keys` | `object` | No | Auto-generated | RSA key pair (`publicKey`, `privateKey` in PEM format) |
| `logger` | `object` | No | `console` | Custom logger with `log` method |

### Users

Each user object must have a `sub` (subject) field, which is the unique identifier used during login and included in all tokens. Any additional fields become available as claims that can be included in tokens based on the requested scopes.

```json
{
  "users": [
    {
      "sub": "user1",
      "given_name": "John",
      "family_name": "Doe",
      "email": "john.doe@example.com",
      "email_verified": true,
      "role": "admin",
      "department": "Engineering"
    }
  ]
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `sub` | Yes | Unique identifier for the user (used as login username) |
| `*` | No | Any additional fields become available as claims |

The `sub` value is what users enter in the login form. All other fields are optional and can be any valid JSON value (strings, numbers, booleans, objects, arrays).

### Base Claims

The `baseClaims` object defines claims that are included for **all users**. This is useful for organization-wide attributes that apply to every user.

```json
{
  "baseClaims": {
    "organization": "Acme Corp",
    "tenant_id": "tenant-123",
    "environment": "development"
  }
}
```

Base claims are merged with user-specific claims when building tokens. If a user has a claim with the same name as a base claim, the **user's value takes precedence**.

Example with precedence:
```json
{
  "baseClaims": {
    "role": "user",
    "organization": "Acme Corp"
  },
  "users": [
    { "sub": "admin", "role": "admin" },
    { "sub": "guest" }
  ]
}
```

- User `admin` will have `role: "admin"` (user value overrides base claim)
- User `guest` will have `role: "user"` (inherits from base claims)
- Both users will have `organization: "Acme Corp"`

### Scopes and Claims Mapping

The `scopes` configuration maps OAuth scope names to arrays of claim names. When a client requests specific scopes during authorization, only the claims associated with those scopes are included in the ID token.

```json
{
  "scopes": {
    "profile": ["given_name", "family_name", "picture"],
    "email": ["email", "email_verified"],
    "roles": ["role", "department"],
    "organization": ["organization", "tenant_id"]
  }
}
```

**How it works:**

1. Client requests scopes: `scope=openid profile email`
2. Server looks up which claims map to `profile` and `email`
3. For each claim name, the server looks up the value from the merged user attributes (baseClaims + user)
4. Only those claims are included in the token

**Example:**

Given this configuration:
```json
{
  "users": [
    {
      "sub": "user1",
      "given_name": "John",
      "family_name": "Doe",
      "email": "john@example.com",
      "role": "admin"
    }
  ],
  "baseClaims": {
    "organization": "Acme Corp"
  },
  "scopes": {
    "profile": ["given_name", "family_name"],
    "email": ["email"],
    "custom": ["role", "organization"]
  }
}
```

| Requested Scopes | Claims in Token |
|------------------|-----------------|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce` (standard claims only) |
| `openid profile` | above + `given_name`, `family_name` |
| `openid profile email` | above + `email` |
| `openid custom` | standard + `role`, `organization` |
| `openid profile email custom` | all configured claims |

**Notes:**
- The `openid` scope is always supported and doesn't need to be configured
- Standard JWT claims (`sub`, `iss`, `aud`, `exp`, `iat`, `nonce`) are always included regardless of scopes
- If a scope references a claim that doesn't exist on the user or baseClaims, it will be `undefined` in the token
- Scopes not defined in the configuration are ignored (no error)

### Key Management

If no keys are provided, the server auto-generates an RSA key pair and saves it to `src/.keys/` for reuse across restarts. You can also provide keys via:
- The `keys` configuration option
- Environment variables: `PUBLIC_KEY_PEM` and `PRIVATE_KEY_PEM`

## API Endpoints

### Authorization

```
GET /oauth/authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid&state=...&nonce=...&code_challenge=...&code_challenge_method=S256
```

Displays a login form. After login, redirects to `redirect_uri` with an authorization code.

### Token Exchange

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

code=...&code_verifier=...
```

Returns:
```json
{
  "access_token": "eyJhbG...",
  "id_token": "eyJhbG...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### UserInfo

```
GET /userinfo
Authorization: Bearer <access_token>
```

Returns user claims (baseClaims merged with user object):
```json
{
  "sub": "user1",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john.doe@example.com",
  "organization": "My Company"
}
```

### Logout

```
GET /logout?post_logout_redirect_uri=...&id_token_hint=...&state=...
```

Clears the session and optionally redirects to `post_logout_redirect_uri`.

## Local Development

### Prerequisites

- Node.js v22+ (see `.nvmrc`)

### Setup and Run

```bash
git clone https://github.com/timojokinen/oidc-mock-server.git
cd oidc-mock-server
npm install

# Start the OIDC server (watch mode)
npm run run:server

# In another terminal, start the test client
npm run run:client
```

The server runs on `http://localhost:3000`, the test client on `http://localhost:4000`.

### Testing the Flow

1. Open `http://localhost:4000`
2. Enter a username (`user1`, `user2`, or `user3` from default config)
3. Click "Login"
4. View your user information on the client

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `HOST` | `http://localhost` | Server host (used for issuer URL) |
| `CONFIG_PATH` | `./server-config.json` | Path to configuration file |
| `PUBLIC_KEY_PEM` | - | PEM-encoded public key |
| `PRIVATE_KEY_PEM` | - | PEM-encoded private key |

### Building

```bash
npm run build          # Build npm package
npm run build:server   # Build standalone server
```

## License

ISC