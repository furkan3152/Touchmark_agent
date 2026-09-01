# Security Policy

The AgentVeritas Stellar team takes the security of our evidence-first verification and audit system very seriously. We appreciate your efforts to responsibly disclose your findings.

## Supported Versions

Only the current major version is actively supported with security updates. 

| Version | Supported          |
| ------- | ------------------ |
| v1.x.x  | :white_check_mark: |
| < v1.0  | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in AgentVeritas Stellar, please do **not** open a public issue.

Instead, please send an email to **security@agentveritas.dev**. 

### What to Expect

- We will acknowledge receipt of your vulnerability report within **48 hours**.
- We will send you regular updates about our progress in verifying and addressing the issue.
- Once the vulnerability is resolved, we will publish a security advisory and credit you for the discovery (unless you prefer to remain anonymous).

## Scope

The following components are considered **in scope** for our bug bounty and security review processes:

- **Soroban Smart Contracts**: Any vulnerabilities allowing unauthorized access, evidence tampering, bypass of audit checks, or draining of funds.
- **Python Backend**: Logic flaws, improper authentication/authorization, data leaks, or evidence forgery.
- **API Endpoints**: Injection attacks, SSRF, broken access control, or other OWASP Top 10 vulnerabilities affecting the production services.

## Out of Scope

The following are explicitly **out of scope**:

- **Testnet/Futurenet Deployments**: Vulnerabilities that only affect test networks and cannot be replicated on Mainnet.
- **Third-Party Dependencies**: Vulnerabilities in upstream libraries (e.g., stellar-sdk, external crates). Please report these to the respective upstream maintainers.
- **Denial of Service (DoS)**: Volumetric DDoS attacks against our public APIs or demo environments.
- Issues requiring excessive social engineering or physical access to developer hardware.
