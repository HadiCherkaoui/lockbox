# Lockbox API Documentation

This document describes the API endpoints for the Lockbox password manager.

## Authentication Flow

Lockbox uses Ed25519 keypair-based authentication similar to SSH and WireGuard, eliminating the need for traditional passwords. The authentication flow involves three steps:

1. **Challenge Generation**: Client requests a challenge from the server
2. **Signature Creation**: Client signs the challenge with their private key
3. **Verification**: Client sends the signed challenge back to the server for verification

After successful authentication, the server returns a JWT token for subsequent API calls.

## API Endpoints

### Authentication Routes

#### `POST /auth/register`
Register a new public key with an associated label.

**Headers:**
- `X-API-KEY`: Admin API key for registration
- `Content-Type`: `application/json`

**Request Body:**
```json
{
  "public_key": [byte_array_as_numbers],
  "label": "string_label_for_the_key"
}
```

**Response:**
```json
{
  "message": "Key registered successfully"
}
```

#### `POST /auth/challenge`
Request a challenge for authentication.

**Headers:**
- `Content-Type`: `application/json`

**Request Body:**
```json
{
  "public_key": [byte_array_as_numbers]
}
```

**Response:**
```json
{
  "challenge": [byte_array_as_numbers]
}
```

#### `POST /auth/verify`
Verify the signed challenge to obtain a JWT token.

**Headers:**
- `Content-Type`: `application/json`

**Request Body:**
```json
{
  "public_key": [byte_array_as_numbers],
  "challenge": [byte_array_as_numbers],
  "signature": [byte_array_as_numbers]
}
```

**Response:**
```json
{
  "success": true,
  "token": "jwt_token_for_subsequent_api_calls"
}
```

### Secrets Management Routes (Protected)

All routes in this section require a valid JWT token in the Authorization header:
`Authorization: Bearer <jwt_token>`

#### `POST /secrets`
Create or update a secret. Each secret belongs to a Kubernetes namespace and is identified by its name within that namespace.

**Headers:**
- `Authorization`: `Bearer <jwt_token>`
- `Content-Type`: `application/json`

**Request Body:**
```json
{
  "namespace": "prod",
  "name": "secret_name",
  "secret": {
    "data": {
      "field_name": {
        "nonce": [12-byte_array_as_numbers],
        "data": [byte_array_as_numbers]
      }
    }
  }
}
```

**Response:**
```json
{
  "success": true
}
```

#### `GET /secrets`
List all secret names.

**Headers:**
- `Authorization`: `Bearer <jwt_token>`

**Response:**
```json
{
  "names": ["secret_name1", "secret_name2"]
}
```

#### `GET /secrets/{name}`
Retrieve a specific secret.

**Headers:**
- `Authorization`: `Bearer <jwt_token>`

**Response:**
```json
{
  "secret": {
    "data": {
      "field_name": {
        "nonce": [12-byte_array_as_numbers],
        "data": [byte_array_as_numbers]
      }
    }
  }
}
```

#### `PATCH /secrets/{name}`
Update an existing secret.

**Headers:**
- `Authorization`: `Bearer <jwt_token>`
- `Content-Type`: `application/json`

**Request Body:**
```json
{
  "data": {
    "field_name": {
      "nonce": [12-byte_array_as_numbers],
      "data": [byte_array_as_numbers]
    }
  }
}
```

**Response:**
```json
{
  "success": true
}
```

#### `DELETE /secrets/{name}`
Soft-delete a secret (creates a tombstone). The record remains for the retention window so controllers can observe the deletion. The `deleted_at` timestamp is set server-side.

**Headers:**
- `Authorization`: `Bearer <jwt_token>`

**Response:**
```json
{
  "success": true
}
```

### Health Check Route

#### `GET /health`
Check the health status of the server.

**Response:**
```json
{
  "status": "healthy"
}
```

## Data Structures

### Secret
A secret contains encrypted data organized as key-value pairs:

```json
{
  "data": {
    "key1": {
      "nonce": [12-byte_array_as_numbers],
      "data": [encrypted_byte_array_as_numbers]
    },
    "key2": {
      "nonce": [12-byte_array_as_numbers],
      "data": [encrypted_byte_array_as_numbers]
    }
  }
}
```

### Ciphertext
Each encrypted field consists of:
- `nonce`: A 12-byte array used for encryption
- `data`: The encrypted byte array

### Secret Metadata

Delta responses include additional metadata per secret:

```json
{
  "namespace": "prod",
  "name": "db-creds",
  "data": { ... },
  "created_at": 1705665600,
  "updated_at": 1705752000,
  "deleted_at": null
}
```

When `deleted_at` is not `null`, the record is a tombstone that indicates the secret was deleted at the given timestamp.

### Delta Synchronization

#### `GET /secrets/sync`
Fetch all secrets created/updated/deleted after a specific timestamp. Useful for Kubernetes controllers performing delta syncs.

**Query Parameters:**
- `since` *(optional)*: Unix timestamp; when omitted, all active secrets are returned.
- `limit` *(optional)*: Maximum number of records to return (default 1000).

**Response:**
```json
{
  "secrets": [
    {
      "namespace": "prod",
      "name": "db-creds",
      "data": { ... },
      "created_at": 1705665600,
      "updated_at": 1705752000,
      "deleted_at": null
    }
  ],
  "server_time": 1705752600
}
```

Clients should store `server_time` and use it as the next `since` value to achieve idempotent delta syncs. Include tombstones (`deleted_at != null`) when cleaning up downstream resources.

## Environment Variables

The server requires the following environment variables:
- `API_KEY`: Admin key for registration
- `JWT_SECRET`: Secret for JWT token signing
- `DATABASE_URL`: Database connection string (defaults to sqlite://lockbox.db)

## Error Handling

All API endpoints return standard HTTP status codes:
- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request format
- `401 Unauthorized` - Authentication failed
- `404 Not Found` - Resource does not exist
- `422 Unprocessable Entity` - Validation error
- `500 Internal Server Error` - Server error