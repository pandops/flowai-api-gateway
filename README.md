# FlowAI API Gateway

The Gateway owns OIDC login and callbacks, encrypted operator sessions,
issuer-to-team mappings, and working-token issuance. It forwards team-scoped
UI operations through NATS and proxies authenticated team WebSocket streams
to Journal. Its embedded SQL migrations manage the Gateway schema.

The production image listens on port 8080 by default. Configure it with
environment variables using `config.env.example` as a reference. Register the
exact `API_GATEWAY_OIDC_REDIRECT_URI` with the identity provider. Supply the
32-byte session key as hex, the signing key as base64 PEM, database credentials,
Journal token, and NATS credentials through your runtime secret provider.
Keep the migration and runtime PostgreSQL roles separate and mount their CA.
The OIDC provider must publish the configured team claim for the client.

## Qualification

Dispatch the read-only workflow from the reviewed candidate branch with its
full commit SHA and the nine publisher SHAs. The workflow stages the Gitea
selector's declared schema inputs under the runner's temporary directory.
It verifies each raw body by SHA-256, runs the Go unit suite, runs the tagged
suite with owned PostgreSQL and NATS containers, verifies their absence, and
builds the production image locally on the runner. The integration step
provisions an isolated database for `TestMappingStoreAtomicRegistration`.
