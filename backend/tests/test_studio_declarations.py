"""Studio: the import bundle contract, a .tmark that is used, and signing code imported first."""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from backend.app.config import Settings
from backend.app.services.studio import ReviewRequest, review_source
from backend.app.services.studio_intake import import_rank

ROOT = Path(__file__).resolve().parents[2]
HONEST = Path(__file__).parent / "fixtures/honest_declarations"


def test_the_bundle_the_server_exports_is_one_the_frontend_accepts():
    """GitHub import returned agent_signing_key, which the page's whitelist did not list, so every
    import failed with "Unknown bundle fields". Both sides now name every ReviewRequest field."""
    script = (ROOT / "frontend/studio.js").read_text()
    allowed = set(json.loads("[" + re.search(r'const allowed = new Set\(\[(.*?)\]\);', script).group(1) + "]"))
    bundle = ReviewRequest(name="Repository source", purpose="Inspect the selected repository source.",
                           files={"a.py": "x = 1\n"}).model_dump(mode="json")
    assert set(bundle) == set(ReviewRequest.model_fields) == allowed
    # And the page sends both back, so a re-run keeps them.
    assert "tmark:tmarkText" in script and "agent_signing_key:agentSigningKey" in script


def _request(**extra) -> ReviewRequest:
    root = HONEST / "syronlabs"
    files = {str(p.relative_to(root)): p.read_text() for p in root.rglob("*.ts")}
    return ReviewRequest(name="stellar-mcp", purpose="Sends payments and builds contracts for the caller.",
                         files=files, **extra)


def _ids(out: dict) -> set[str]:
    return {f["id"] for f in out["report"]["findings"]}


def test_studio_uses_a_tmark_as_the_repository_would():
    text = (HONEST / "syronlabs/.tmark").read_text()
    bare = asyncio.run(review_source(_request(), Settings(_env_file=None)))
    declared = asyncio.run(review_source(_request(tmark=text), Settings(_env_file=None)))
    record = declared["report"]["declarations"]["tmark"]
    assert record["status"] == "valid" and record["source"] == "supplied" and record["summary"]
    assert bare["report"]["declarations"]["tmark"] == {"status": "missing"}
    tools = {t["name"]: t for t in declared["report"]["agent"]["tools"]}
    assert tools["stellar_payment"]["origin"] == "declared" and tools["stellar_payment"]["requires_signature"]
    assert "economic-no-mev-protection" not in _ids(declared)
    assert declared["report"]["result"]["overall_score"] >= bare["report"]["result"]["overall_score"]


def test_a_tmark_in_an_uploaded_folder_is_the_declaration_not_a_hidden_source_file():
    text = (HONEST / "syronlabs/.tmark").read_text()
    request = ReviewRequest.model_validate({"name": "a", "purpose": "Sends payments for the caller.",
                                            "files": {"src/a.ts": "export const a = 1;\n", ".tmark": text}})
    assert request.tmark == text and ".tmark" not in request.files
    invalid = asyncio.run(review_source(_request(tmark='{"tmark": "1"}'), Settings(_env_file=None)))
    assert invalid["report"]["declarations"]["tmark"]["status"] == "invalid"
    assert "intent-tmark-invalid" in _ids(invalid)


def test_github_import_takes_the_signing_code_before_configuration_and_tests():
    paths = ["LICENSE", "README.md", "docker-compose.yml", "eslint.config.js", "jest.config.js", "package.json",
             "tsconfig.json", "src/index.ts", "src/config/environment.config.ts", "src/interfaces/common.interface.ts",
             "src/interfaces/soroban/Commands.ts", "src/stellar/classic/__tests__/classic.test.ts",
             "src/stellar/classic/classic.ts", "src/stellar/classic/schemas.ts", "src/stellar/core/core.ts",
             "src/stellar/core/messages.ts", "src/stellar/soroban/soroban.ts", "src/tools/classic.ts",
             "src/tools/soroban.ts", "src/tools/tools.ts", "docs/CONTRIBUTING.md"]
    ranked = [p for p in sorted(({"path": p} for p in paths), key=import_rank)][:12]
    first = [item["path"] for item in ranked]
    for signing in ("src/stellar/classic/classic.ts", "src/stellar/soroban/soroban.ts", "src/stellar/core/core.ts"):
        assert signing in first
    assert first[0] == "package.json"
    assert first.index("src/stellar/classic/classic.ts") < first.index("src/index.ts")
    assert not {"jest.config.js", "eslint.config.js", "src/stellar/classic/__tests__/classic.test.ts"} & set(first)


def test_github_import_carries_the_repository_tmark_in_the_bundle(monkeypatch):
    import base64
    from hashlib import sha1

    import httpx
    from fastapi.testclient import TestClient

    from backend.app import api
    source = b'def answer(prompt):\n    return "Read only"\n'
    mark = (HONEST / "syronlabs/.tmark").read_bytes()
    blobs = {sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest(): raw for raw in (source, mark)}
    by_path = {"src/reader.py": source, ".tmark": mark}
    revision = "b" * 40

    async def respond(self, request, **kwargs):
        url = str(request.url)
        if url.endswith("/commits/HEAD"):
            data = {"sha": revision}
        elif url.endswith(f"/git/trees/{revision}?recursive=1"):
            data = {"tree": [{"type": "blob", "mode": "100644", "path": p, "size": len(raw),
                              "sha": sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()} for p, raw in by_path.items()]}
        else:
            data = {"encoding": "base64", "content": base64.b64encode(blobs[url.rsplit("/", 1)[1]]).decode()}
        return httpx.Response(200, json=data, request=request)
    monkeypatch.setattr(httpx.AsyncClient, "send", respond)
    with TestClient(api.app, client=("192.0.2.78", 50000)) as client:
        bundle = client.post("/api/v1/studio/import", json={"repository": "https://github.com/example/reader"}).json()["bundle"]
    assert bundle["tmark"] == mark.decode() and set(bundle["files"]) == {"src/reader.py"}
    assert "agent_signing_key" in bundle  # the field that broke every import, now accepted by the page
