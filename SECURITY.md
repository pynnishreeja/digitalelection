# Security configuration

## Required environment variables

The authentication and vote services require `JWT_SECRET`. It must contain
at least 32 UTF-8 bytes (256 bits) for HMAC signing. Both services must use
the same value so that tokens issued by the authentication service can be
validated by the vote service. Generate a fresh random value for each
environment, for example:

```bash
openssl rand -base64 32
```

All four database-backed services require `DB_USERNAME` and
`DB_PASSWORD`. Set these variables in the process environment or deployment
secret manager before starting the services. Use a dedicated database
account with only the permissions required by the service, not the MySQL
root account.

The `.env.example` file documents the expected variable names and contains
placeholders only. Replace them in your local environment; do not commit
populated secret files.

## Previously exposed credentials

The JWT signing key and database password previously committed to this
repository must be considered compromised. Rotate the JWT secret and DB
credentials in every environment where they were used. Rotation does not
remove secrets from Git history. Coordinate a history rewrite with the
repository maintainers and notify contributors before force-pushing rewritten
history.
