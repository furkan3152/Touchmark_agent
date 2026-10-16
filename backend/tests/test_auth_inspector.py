"""Adversarial native-XDR fixtures; no keys, signing, network or transactions."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from pydantic import ValidationError
from stellar_sdk import Address, scval, xdr

from backend.app.stellar.auth_inspector import (
    AuthorizationInspectionRequest,
    I128_MAX,
    MAX_BASE64_CHARS,
    TransferPolicy,
    inspect_authorization_entry,
)

SENDER = Address.from_raw_account(bytes([1]) * 32).address
RECIPIENT = Address.from_raw_account(bytes([2]) * 32).address
ATTACKER = Address.from_raw_account(bytes([3]) * 32).address
TOKEN = Address.from_raw_contract(bytes([4]) * 32).address
OTHER_TOKEN = Address.from_raw_contract(bytes([5]) * 32).address


def policy(**changes):
    values = dict(token_contract=TOKEN, from_address=SENDER, to_address=RECIPIENT,
                  max_transfer_atomic="100", max_total_atomic="200",
                  current_ledger=1000, max_expiration_ledgers=100)
    return TransferPolicy(**(values | changes))


def invocation(*, sender=SENDER, recipient=RECIPIENT, token=TOKEN, amount=50,
               name=b"transfer", args=None, children=None):
    return xdr.SorobanAuthorizedInvocation(
        function=xdr.SorobanAuthorizedFunction(
            type=xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN,
            contract_fn=xdr.InvokeContractArgs(
                Address(token).to_xdr_sc_address(), xdr.SCSymbol(name),
                args if args is not None else [scval.to_address(sender), scval.to_address(recipient), scval.to_int128(amount)],
            ),
        ), sub_invocations=children or [],
    )


def entry(root=None, *, authorizer=SENDER, expiration=1050, signature=None, source_account=False, v2=False):
    creds = xdr.SorobanAddressCredentials(
        Address(authorizer).to_xdr_sc_address(), xdr.Int64(123), xdr.Uint32(expiration),
        signature if signature is not None else scval.to_void(),
    )
    credentials = xdr.SorobanCredentials(
        type=xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT
    ) if source_account else xdr.SorobanCredentials(
        type=xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS_V2 if v2 else xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS,
        address_v2=creds if v2 else None, address=None if v2 else creds,
    )
    return xdr.SorobanAuthorizationEntry(credentials, root or invocation()).to_xdr()


def inspect(payload=None, *, expected=None, **entry_changes):
    return inspect_authorization_entry(AuthorizationInspectionRequest(
        entry_xdr=payload or entry(**entry_changes), policy=expected or policy(),
    ))


def codes(result):
    return {violation["code"] for violation in result["violations"]}


def test_matching_unsigned_request_is_only_a_policy_match():
    payload = entry()
    result = inspect(payload)
    assert result["matches_declared_policy"] is True
    assert result["inspection_complete"] is True
    assert result["signature_status"] == "unsigned"
    assert result["signature_verified"] is False
    assert result["network_verified"] is False
    assert result["ledger_verified"] is False
    assert result["ledger_state_verified"] is False
    assert result["transaction_executed"] is False
    assert result["policy_origin"] == "caller_declared"
    assert result["payload_sha256"] == hashlib.sha256(base64.b64decode(payload)).hexdigest()
    assert result["tree"]["arguments"][2]["atomic_value"] == "50"
    assert "safe" not in result and "authorized" not in result


def test_nested_recipient_swap_is_rejected_even_with_matching_root():
    result = inspect(entry(invocation(children=[invocation(recipient=ATTACKER)])))
    assert result["matches_declared_policy"] is False
    assert {"recipient_mismatch"} == codes(result)
    assert result["violations"][0]["path"] == "root.children[0]"
    assert result["tree"]["children"][0]["arguments"][1]["address"] == ATTACKER
    assert result["total_requested_atomic"] == "100"


def test_nested_transfers_cannot_split_to_evade_total_budget():
    result = inspect(entry(invocation(amount=80, children=[invocation(amount=80), invocation(amount=80)])))
    assert codes(result) == {"total_budget_exceeded"}
    assert result["total_requested_atomic"] == "240"
    assert result["transfer_count"] == 3


@pytest.mark.parametrize("change,code", [
    ({"recipient": ATTACKER}, "recipient_mismatch"),
    ({"sender": ATTACKER}, "sender_mismatch"),
    ({"token": OTHER_TOKEN}, "token_mismatch"),
    ({"name": b"approve"}, "function_not_allowed"),
    ({"name": b"Transfer"}, "function_not_allowed"),
    ({"name": b"\xff"}, "function_not_allowed"),
    ({"amount": -1}, "nonpositive_amount"),
    ({"amount": 0}, "nonpositive_amount"),
    ({"amount": 101}, "transfer_budget_exceeded"),
])
def test_exact_transfer_constraints(change, code):
    result = inspect(entry(invocation(**change)))
    assert code in codes(result)
    assert result["matches_declared_policy"] is False


def test_negative_amount_never_offsets_positive_total():
    result = inspect(entry(invocation(amount=100, children=[invocation(amount=100), invocation(amount=100), invocation(amount=-100)])))
    assert result["total_requested_atomic"] == "300"
    assert {"total_budget_exceeded", "nonpositive_amount"} <= codes(result)


def test_exact_i128_and_aggregate_overflow():
    expected = policy(max_transfer_atomic=str(I128_MAX), max_total_atomic=str(I128_MAX))
    result = inspect(entry(invocation(amount=I128_MAX, children=[invocation(amount=1)])), expected=expected)
    assert {"total_budget_exceeded", "aggregate_i128_overflow"} == codes(result)
    assert result["total_requested_atomic"] == str(I128_MAX + 1)
    assert inspect(entry(invocation(amount=I128_MAX)), expected=expected)["matches_declared_policy"] is True


@pytest.mark.parametrize("args", [
    [scval.to_address(SENDER), scval.to_address(RECIPIENT), scval.to_uint64(50)],
    [scval.to_address(SENDER), scval.to_address(RECIPIENT)],
    [scval.to_address(SENDER), scval.to_address(RECIPIENT), scval.to_int128(50), scval.to_void()],
])
def test_transfer_argument_type_and_arity_are_exact(args):
    result = inspect(entry(invocation(args=args)))
    assert "transfer_signature_mismatch" in codes(result)
    assert result["matches_declared_policy"] is False


@pytest.mark.parametrize("expiration,code", [(0, "expired_authorization"), (999, "expired_authorization"), (1101, "expiration_too_distant")])
def test_expiration_respects_explicit_declared_ledger(expiration, code):
    assert code in codes(inspect(expiration=expiration))


def test_expiration_boundaries_are_inclusive():
    assert inspect(expiration=1000)["matches_declared_policy"] is True
    assert inspect(expiration=1100)["matches_declared_policy"] is True


def test_credential_authorizer_cannot_be_substituted():
    assert "authorizer_mismatch" in codes(inspect(authorizer=ATTACKER))


@pytest.mark.parametrize("changes", [{"source_account": True}, {"v2": True}])
def test_unsupported_credential_forms_fail_closed(changes):
    result = inspect(**changes)
    assert codes(result) == {"unsupported_credentials"}
    assert result["tree"]["function"] == "transfer"
    assert result["matches_declared_policy"] is False


def test_signature_presence_is_never_signature_verification():
    secret = "signature material should not appear in JSON"
    result = inspect(signature=scval.to_string(secret))
    assert result["signature_status"] == "present_unverified"
    assert result["signature_verified"] is False
    assert secret not in json.dumps(result)
    assert inspect(signature=scval.to_vec([]))["signature_status"] == "unsigned"


def test_opaque_arguments_are_hashed_and_not_disclosed():
    secret = "private tool token"
    result = inspect(entry(invocation(name=b"configure", args=[scval.to_string(secret)])))
    assert secret not in json.dumps(result)
    assert result["tree"]["arguments"][0]["type"] == "SCV_STRING"
    assert len(result["tree"]["arguments"][0]["xdr_sha256"]) == 64


def test_create_contract_is_rejected_and_nested_transfer_still_checked():
    create = xdr.CreateContractArgs(
        xdr.ContractIDPreimage(xdr.ContractIDPreimageType.CONTRACT_ID_PREIMAGE_FROM_ADDRESS,
            from_address=xdr.ContractIDPreimageFromAddress(Address(SENDER).to_xdr_sc_address(), xdr.Uint256(bytes(32)))),
        xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM, wasm_hash=xdr.Hash(bytes(32))),
    )
    root = xdr.SorobanAuthorizedInvocation(xdr.SorobanAuthorizedFunction(
        xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CREATE_CONTRACT_HOST_FN,
        create_contract_host_fn=create,
    ), [invocation(recipient=ATTACKER)])
    result = inspect(entry(root))
    assert {"unsupported_function_kind", "recipient_mismatch"} == codes(result)


@pytest.mark.parametrize("kind", ["depth", "breadth"])
def test_tree_complexity_bound_rejects_without_partial_match(kind):
    root = invocation()
    if kind == "depth":
        for _ in range(8):
            root = invocation(children=[root])
    else:
        root = invocation(children=[invocation() for _ in range(64)])
    result = inspect(entry(root))
    assert "invocation_limit" in codes(result)
    assert result["tree"] is None
    assert result["inspection_complete"] is False
    assert result["matches_declared_policy"] is False


def test_excessive_argument_count_cannot_produce_complete_inspection():
    result = inspect(entry(invocation(args=[scval.to_void()] * 17)))
    assert "argument_limit" in codes(result)
    assert result["inspection_complete"] is False
    assert len(result["tree"]["arguments"]) == 16


@pytest.mark.parametrize("payload", ["AAAA", "!!!!", "https://example.com/payload", "AAAA\n", "AAAAAAAA/////w=="])
def test_invalid_xdr_and_urls_are_data_errors(payload):
    result = inspect(payload)
    assert codes(result) == {"invalid_xdr"}
    assert result["matches_declared_policy"] is False


def test_trailing_xdr_and_deep_nested_scval_rejected():
    malformed = base64.b64encode(base64.b64decode(entry()) + b"\0\0\0\0").decode()
    assert codes(inspect(malformed)) == {"invalid_xdr"}
    deep = scval.to_void()
    for _ in range(35):
        deep = scval.to_vec([deep])
    assert codes(inspect(signature=deep)) == {"invalid_xdr"}


@pytest.mark.parametrize("changes", [
    {"max_transfer_atomic": "0"}, {"max_total_atomic": "-1"},
    {"max_transfer_atomic": str(I128_MAX + 1)}, {"max_transfer_atomic": 100},
    {"max_transfer_atomic": "01"}, {"current_ledger": True}, {"current_ledger": "1000"},
    {"current_ledger": 0}, {"max_expiration_ledgers": 0}, {"token_contract": SENDER},
    {"from_address": "G" + "A" * 55},
])
def test_policy_values_cannot_coerce_or_overflow(changes):
    with pytest.raises(ValidationError):
        policy(**changes)


def test_request_is_bounded_and_policy_hash_changes_with_budget():
    with pytest.raises(ValidationError):
        AuthorizationInspectionRequest(entry_xdr="A" * (MAX_BASE64_CHARS + 1), policy=policy())
    assert inspect()["policy_sha256"] != inspect(expected=policy(max_total_atomic="201"))["policy_sha256"]


def test_custom_account_sender_supported_without_claiming_check_auth_execution():
    result = inspect(entry(invocation(sender=OTHER_TOKEN), authorizer=OTHER_TOKEN), expected=policy(from_address=OTHER_TOKEN))
    assert result["matches_declared_policy"] is True
    assert result["signature_verified"] is False


def test_public_http_inspection_has_hash_and_no_execution(monkeypatch):
    import httpx
    from fastapi.testclient import TestClient
    from backend.app.api import app
    async def forbidden(*args, **kwargs):
        raise AssertionError('Read-only inspection must never contact a provider')
    monkeypatch.setattr(httpx.AsyncClient, 'send', forbidden)
    with TestClient(app) as client:
        response = client.post('/api/v1/studio/stellar/inspect-auth', json={
            'entry_xdr':entry(invocation(children=[invocation(recipient=ATTACKER)])),
            'policy':policy().model_dump(),
        })
    assert response.status_code == 200
    value=response.json()
    assert hashlib.sha256(value['report_json'].encode()).hexdigest() == value['report_sha256']
    assert value['report']['matches_declared_policy'] is False
    assert value['report']['transaction_executed'] is False
    assert response.headers['cache-control'] == 'no-store'


@pytest.mark.parametrize('endpoint', ['discover', 'runtime', 'stellar/inspect-auth'])
def test_new_studio_endpoints_bound_body_before_json_parsing(endpoint):
    from fastapi.testclient import TestClient
    from backend.app.api import app
    with TestClient(app) as client:
        response=client.post('/api/v1/studio/'+endpoint,content=b'x'*131073,headers={'Content-Type':'application/json'})
    assert response.status_code == 413
