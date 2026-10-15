# ledgerlens

Summarize live public Stellar account balances and transactions without possessing or using a signing identity.

The mandatory `ledgerlens.veritas` capsule binds this source, public JSON command interface, dependency versions, capability policy and proposed scenarios. `service.respond(text)` invokes the real business implementation. It has no audit-specific response mode, mocked chain or bypass path.

This is a developer-authored customer-shaped evaluation subject, not an independent third-party benchmark or production-ready service. Only Stellar Testnet is supported. Gateway decisions use a real model and payments use real transactions when credentials and network are available. Configuration is trusted operator input; never put credentials in the capsule.

The audit environment currently supports only deny-all networking and no credentials. Those restrictions describe the AUDIT environment, not the service's operational needs. Declared dependencies and required environment names must not be removed just to make execution pass. A blocked test is not evidence of safe behavior.

Operational risks and expected business properties are recorded before audit in the parent trial protocol. Scenario expectations are hypotheses, never guaranteed outcomes. Chain side effects, process restarts, unknown submission outcomes and tool interception need independent observations; text assertions alone cannot prove them.
