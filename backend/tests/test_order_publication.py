from __future__ import annotations

import asyncio
from hashlib import sha256
from types import SimpleNamespace

import httpx
import pytest

from backend.app.reporting.generator import canonical_json
from backend.app.services.order_publication import MAX_REPORT_BYTES, PrivateReportPublisher, PublicationError

STORE = "ExampleStore1234"
TOKEN = f"vercel_blob_rw_{STORE}_testcredential"
ORIGIN = f"https://{STORE.lower()}.private.blob.vercel-storage.com"
ORDER = {"id": "order-test", "consents": {"storage_consent": True, "publication_consent": True}}


def result(**changes):
    report = {"agent": {"name": "Private storage fixture"}, "findings": [], "review_decision": "needs_evidence"} | changes
    encoded = canonical_json(report)
    return {"report": report, "report_json": encoded, "report_sha256": sha256(encoded.encode()).hexdigest()}


class Store:
    def __init__(self):
        self.objects = {}
        self.calls = []
        self.uploads = []
        self.closed = 0
        self.response_url = None
        self.upload_error = None
        self.read_handler = None

    def factory(self, *, token):
        assert token == TOKEN
        owner = self

        class Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                owner.closed += 1

            async def put(self, path, body, **kwargs):
                owner.uploads.append({"path": path, "body": body, **kwargs})
                if owner.upload_error:
                    raise owner.upload_error
                if path in owner.objects:
                    raise RuntimeError("Blob already exists")
                owner.objects[path] = body
                return SimpleNamespace(url=owner.response_url or f"{ORIGIN}/{path}", pathname=path)

        return Client()

    def read(self, request):
        self.calls.append(request)
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert str(request.url).startswith(ORIGIN + "/reports/")
        assert request.url.params["cache"] == "0"
        if self.read_handler:
            return self.read_handler(request)
        body = self.objects.get(request.url.path.lstrip("/"))
        return httpx.Response(200 if body else 404, content=body or b"", headers={"content-type": "application/json"})

    def publisher(self, **settings):
        config = SimpleNamespace(blob_read_write_token=TOKEN, blob_store_id=f"store_{STORE}", **settings)
        return PrivateReportPublisher(config, blob_client_factory=self.factory, read_transport=httpx.MockTransport(self.read))


def test_private_upload_exact_bytes_then_readback(run):
    store = Store()
    envelope = result()
    publisher = store.publisher()
    publication = run(publisher.publish(ORDER, envelope))
    assert publication["status"] == "verified" and publication["verified"] is True
    assert publication["visibility"] == "private"
    assert publication["report_sha256"] == envelope["report_sha256"]
    assert publication["report_uri"] == f"{ORIGIN}/reports/{envelope['report_sha256']}.json"
    assert publication["write_outcome"] == "created"
    assert store.uploads == [{"path": f"reports/{envelope['report_sha256']}.json", "body": envelope["report_json"].encode(),
        "access": "private", "content_type": "application/json", "add_random_suffix": False, "overwrite": False, "multipart": False}]
    assert store.closed == 1
    assert TOKEN not in str(publication) and TOKEN not in repr(publisher)
    assert run(publisher.verify(publication, envelope["report_json"].encode())) is True


def test_retry_reconciles_existing_bytes_without_overwriting(run):
    store = Store()
    publisher = store.publisher()
    envelope = result()
    first = run(publisher.publish(ORDER, envelope))
    second = run(publisher.publish(ORDER, envelope))
    assert first["report_uri"] == second["report_uri"]
    assert second["write_outcome"] == "reconciled_existing"
    assert len(store.objects) == 1
    assert all(call["overwrite"] is False for call in store.uploads)


def test_uncertain_write_is_reconciled_only_if_exact_bytes_exist(run):
    store = Store()
    envelope = result()
    store.objects[f"reports/{envelope['report_sha256']}.json"] = envelope["report_json"].encode()
    store.upload_error = TimeoutError(TOKEN)
    assert run(store.publisher().publish(ORDER, envelope))["write_outcome"] == "reconciled_existing"
    store.objects.clear()
    with pytest.raises(PublicationError) as caught:
        run(store.publisher().publish(ORDER, envelope))
    assert TOKEN not in str(caught.value)


@pytest.mark.parametrize("consents", [{}, {"storage_consent": True}, {"storage_consent": "true", "publication_consent": True}])
def test_missing_explicit_consent_never_uploads(run, consents):
    store = Store()
    with pytest.raises(PublicationError, match="consent"):
        run(store.publisher().publish({"consents": consents}, result()))
    assert store.uploads == [] and store.calls == []


@pytest.mark.parametrize("key", ["files", "code_files", "source_files", "source_code", "raw_source", "source_bundle", "system_prompt"])
def test_raw_source_bundle_never_uploaded(run, key):
    store = Store()
    envelope = result(extra={key: {"main.py": "print('private source')"}})
    with pytest.raises(PublicationError):
        run(store.publisher().publish(ORDER, envelope))
    assert store.uploads == []


@pytest.mark.parametrize("kind", ["wrong_hash", "wrong_report", "noncanonical", "oversized", "not_report"])
def test_invalid_report_envelope_never_uploaded(run, kind):
    store = Store()
    envelope = result()
    if kind == "wrong_hash":
        envelope["report_sha256"] = "0" * 64
    elif kind == "wrong_report":
        envelope["report"]["agent"]["name"] = "different"
    elif kind == "noncanonical":
        envelope["report_json"] += "\n"
        envelope["report_sha256"] = sha256(envelope["report_json"].encode()).hexdigest()
    elif kind == "oversized":
        envelope = result(note="x" * MAX_REPORT_BYTES)
    else:
        envelope = {"report": {"hello": "world"}, "report_json": '{"hello":"world"}', "report_sha256": sha256(b'{"hello":"world"}').hexdigest()}
    with pytest.raises(PublicationError):
        run(store.publisher().publish(ORDER, envelope))
    assert not store.uploads


@pytest.mark.parametrize("url", [
    "https://attacker.example/report.json", "https://localhost/report.json",
    ORIGIN.replace("private", "public") + "/reports/file.json", ORIGIN + "/reports/file.json?token=secret",
])
def test_wrong_upload_location_fails_without_following_it(run, url):
    store = Store()
    store.response_url = url
    with pytest.raises(PublicationError, match="unexpected"):
        run(store.publisher().publish(ORDER, result()))
    assert not store.calls


@pytest.mark.parametrize("kind", ["redirect", "unauthorized", "wrong_type", "compressed", "length", "changed_body", "truncated"])
def test_readback_failures_cannot_claim_publication(run, kind):
    store = Store()
    envelope = result()
    body = envelope["report_json"].encode()
    responses = {
        "redirect": lambda _: httpx.Response(302, headers={"location": "https://attacker.example/steal"}),
        "unauthorized": lambda _: httpx.Response(403),
        "wrong_type": lambda _: httpx.Response(200, content=body, headers={"content-type": "text/html"}),
        "compressed": lambda _: httpx.Response(200, content=body, headers={"content-type": "application/json", "content-encoding": "unsupported"}),
        "length": lambda _: httpx.Response(200, content=body, headers={"content-type": "application/json", "content-length": str(MAX_REPORT_BYTES + 1)}),
        "changed_body": lambda _: httpx.Response(200, content=b"x" * len(body), headers={"content-type": "application/json"}),
        "truncated": lambda _: httpx.Response(200, content=body[:-1], headers={"content-type": "application/json"}),
    }
    store.read_handler = responses[kind]
    with pytest.raises(PublicationError):
        run(store.publisher().publish(ORDER, envelope))
    assert len(store.calls) == 2
    assert all(str(call.url).startswith(ORIGIN) for call in store.calls)


def test_stream_size_bound_applies_without_content_length(run):
    store = Store()

    class LargeStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * 8192
            raise AssertionError("Oversized response should stop before the second chunk")

    store.read_handler = lambda _: httpx.Response(200, stream=LargeStream(), headers={"content-type": "application/json"})
    with pytest.raises(PublicationError):
        run(store.publisher().publish(ORDER, result()))


@pytest.mark.parametrize("change", [
    {"visibility": "public"}, {"report_sha256": "0" * 64}, {"report_uri": "http://127.0.0.1/"},
    {"report_uri": ORIGIN + "/reports/../secret"}, {"report_uri": ORIGIN + "@attacker.example/report"},
])
def test_verifier_rejects_metadata_before_any_network(run, change):
    store = Store()
    envelope = result()
    receipt = {"report_sha256": envelope["report_sha256"], "report_uri": f"{ORIGIN}/reports/{envelope['report_sha256']}.json", "visibility": "private"} | change
    with pytest.raises(PublicationError):
        run(store.publisher().verify(receipt, envelope["report_json"].encode()))
    assert store.calls == []


@pytest.mark.parametrize("store,token", [("../invalid", TOKEN), ("DifferentStore", TOKEN), (STORE, ""), (STORE, "vercel_blob_rw_other_token")])
def test_configuration_binds_credential_to_exact_store(store, token):
    with pytest.raises(PublicationError) as caught:
        PrivateReportPublisher(SimpleNamespace(blob_read_write_token=token, blob_store_id=store))
    assert token not in str(caught.value) if token else True


def test_sdk_endpoint_override_rejected_before_credential_use(monkeypatch):
    monkeypatch.setenv("VERCEL_BLOB_API_URL", "https://attacker.example")
    with pytest.raises(PublicationError, match="Custom Blob"):
        Store().publisher()


def test_same_report_concurrent_retries_keep_one_immutable_object(run):
    async def execute():
        store = Store()
        publisher = store.publisher()
        envelope = result()
        results = await asyncio.gather(*(publisher.publish(ORDER, envelope) for _ in range(3)))
        assert all(receipt["verified"] for receipt in results)
        assert len(store.objects) == 1
    run(execute())
