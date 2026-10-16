# Registry-bound audit escrow

This contract settles payment for one existing AgentVeritas registry validation request. The escrow `job_id` is exactly the registry `req_id`. A separate invoice identifier is not accepted as an unbound job.

The constructor is `__constructor(admin, token, fee_to, fee_bps, registry)`. The registry address is fixed at construction and exposed through `get_registry`. This changes the deployment ABI; previously deployed generic escrows do not acquire these checks and remain historical deployments.

| Operation | Required evidence and authorization |
| --- | --- |
| `create` | Requester signature; existing registry request; matching requester and assigned validator/provider; active current agent; distinct requester, provider and evaluator; positive exact token amount and future ledger deadline. |
| `fund` | Requester signature; the stored registry identity snapshot is still current; atomic token transfer into escrow. |
| `submit` | Provider signature; completed registry validation; identical report content hash; unchanged agent identity, source hashes and version; currently authorized validator; deadline not elapsed. |
| `submit` (effects) | Records the registry score and opens a review window of `REVIEW_LEDGERS` (17,280 ledgers, about one day) that is independent of the job deadline. |
| `complete` | Evaluator signature inside the review window; the same report hash, registry score and identity checks; provider payout and snapshotted platform fee. |
| `dispute` | Evaluator signature inside the review window. Funds stay locked; the requester cannot refund a disputed job alone. |
| `resolve` | Admin arbitration of a disputed job: refund the requester or pay the provider. Available even when a version became stale or a validator was disabled, so failed validation cannot trap funds. |
| `claim` | Provider signature after an undisputed review window closes. Pays the recorded score's delivery without re-reading registry identity, so a requester-controlled agent update or deactivation after submission cannot cancel payment. |
| `refund` | Requester signature; only a `Funded` job with no submitted report, after the deadline. A delivered report is never refundable by the requester alone. |

Version 0.4.0 changed settlement: in 0.3.0 the requester chose the evaluator and could refund a delivered report through a self-controlled dispute or by letting the deadline pass. Deployed 0.3.0 contracts keep the old rules; the backend refund eligibility in `backend/app/services/order_refunds.py` targets the pinned deployment and must be updated together with a 0.4.0 redeploy.

`get_binding(job_id)` exposes the agent ID, owner, version, metadata hash and source/endpoint hash captured at creation. `get_job` retains its existing response shape. Contract errors `InvalidValidation = 15` and `StaleIdentity = 16` distinguish inconsistent evidence from identity drift; `BadScore = 9` rejects disagreement with the registry score.

The contract proves consistency between a designated validator's registry assertion and settlement. It does not prove the correctness or completeness of that assertion. Different signing keys do not establish that their operators are independent. A report credential proves report provenance; payment status must be read from this escrow separately.

Run the real-registry integration tests with:

```sh
cargo test -p agent-veritas-escrow
```

The Testnet delivery script in `scripts/testnet_audit_delivery.py` publishes a genuine static fixture report, verifies its downloaded bytes, runs settlement and credential issuance, and tests report/score/version mismatches plus a disputed refund. It uses disposable first-party identities and faucet XLM only.
