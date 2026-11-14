# Service Authorization

## JWT-protected endpoints

The auth service issues signed JWTs containing the user's `role` claim. The election and vote services validate the token signature and expiry before creating a Spring Security authentication. All three services must use the same `JWT_SECRET` environment variable (at least 32 UTF-8 bytes). The election service reads this variable directly; the auth and vote services use the same setting after the companion secret-externalization change in PR #3 is merged.

- Public read-only election, candidate, and party endpoints remain available.
- Election and candidate/party mutations require an `ADMIN` token.
- Casting a vote and checking a voter's participation require an authenticated token.
- `GET /api/votes/all` requires the `ADMIN` role.
- Unauthenticated requests to protected endpoints receive HTTP 401; authenticated users without the required role receive HTTP 403.
- New public sign-ups are assigned the `VOTER` role. Administrator accounts must be provisioned through a trusted administrative process; do not allow clients to choose their role during sign-up.

## Internal audit writes

Only trusted services may create audit records. The audit service requires the `X-Internal-Service-Token` header on `POST /api/audit`. The vote service sends this header when recording a vote.

Configure the same strong, randomly generated `INTERNAL_SERVICE_TOKEN` environment variable for both the vote-service and audit-service processes. For example, generate a value with:

```sh
openssl rand -hex 32
```

Do not commit the generated token or place it in client-side code. Requests without a valid token receive HTTP 401. The token is compared using a constant-time comparison.

Audit read and verification endpoints retain their existing access policy; this change specifically protects audit-log creation from untrusted callers.
