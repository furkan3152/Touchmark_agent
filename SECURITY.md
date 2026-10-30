# Security Policy

## Supported versions

Only the current major version receives security fixes.

| Version | Supported |
| ------- | --------- |
| v1.x.x  | Yes       |
| < v1.0  | No        |

## Reporting a vulnerability

Please do not open a public issue for a security problem. Email **security@agentveritas.dev** instead.

We acknowledge reports within 48 hours and keep you updated while we verify and fix the issue. Once it is resolved we publish an advisory and credit you, unless you would rather stay anonymous.

## Scope

In scope for security review and the bug bounty:

- Soroban contracts: unauthorized access, evidence tampering, bypassing audit checks, draining funds.
- Python backend: logic flaws, broken authentication or authorization, data leaks, forged evidence.
- API endpoints: injection, SSRF, broken access control and other OWASP Top 10 issues affecting the production services.

Out of scope:

- Issues that only affect testnet or futurenet deployments and cannot be reproduced on mainnet.
- Vulnerabilities in third-party dependencies such as `stellar-sdk` or external crates. Please report those upstream.
- Volumetric denial-of-service attacks against the public APIs or the demo.
- Issues that require heavy social engineering or physical access to developer hardware.
