# Security Policy

## Supported versions

Touchmark has no numbered releases yet. Security fixes go to the `main` branch and to the live demo
(<https://usetouchmark.app>); nothing else is supported.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through GitHub instead: open the repository's **Security** tab and choose **Report a vulnerability**.

We acknowledge reports within 48 hours and keep you updated while we verify and fix the issue. Once it is resolved we publish an advisory and credit you, unless you would rather stay anonymous. There is no bug bounty.

## Scope

Every deployment is on Stellar testnet, so findings reproduced on testnet are in scope:

- Soroban contracts: unauthorized access, evidence tampering, bypassing audit checks, draining or locking funds.
- Python backend and analysis engine: logic flaws, broken authentication or authorization, data leaks, forged or misleading reports, a way to make an unsafe agent pass.
- API endpoints and the live demo: injection, SSRF, broken access control and other OWASP Top 10 issues.

Out of scope:

- The demo operator's testnet key and the test assets themselves: the key is a throwaway and the assets have no value. A flaw that lets someone misuse that key through the service is in scope.
- Vulnerabilities in third-party dependencies such as `stellar-sdk` or external crates. Please report those upstream.
- Volumetric denial-of-service attacks against the public APIs or the demo.
- Issues that require heavy social engineering or physical access to developer hardware.
