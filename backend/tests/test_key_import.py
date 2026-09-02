"""`scripts/import_keys.py` — correct import of the key file into `.env`.

Because this tool touches keys, it must guarantee two things: mapping aliases
to the correct `.env` fields, and not overwriting existing values with blank lines.
The tests run on the file system, no network calls."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def test_template_file_lists_every_supported_alias(tmp_path):
    """Şablon, desteklenen her ücretsiz/temel anahtarı içermeli.

    Şablon ile ALIASES sözlüğü ayrışırsa kullanıcı doldurduğu satırın sessizce
    yok sayıldığını göremez.
    """
    from scripts.import_keys import ALIASES, TEMPLATE

    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "PINATA_JWT", "CHAINALYSIS_API_KEY"):
        assert name in TEMPLATE, name
        assert name in ALIASES, name
    # OpenRouter varsayılan öneri olduğu için şablonda yorumsuz bulunmalı
    assert "\nOPENROUTER_API_KEY=" in TEMPLATE
    assert "OPENROUTER_API_KEY" in ALIASES


def test_openrouter_alias_sets_provider_and_model(tmp_path):
    """OpenRouter model adları sağlayıcı önekli olmalı; varsayılan da düzeltilir."""
    from scripts.import_keys import parse_key_file

    src = tmp_path / "keys.txt"
    src.write_text("OPENROUTER_API_KEY=sk-or-v1-x\n", encoding="utf-8")
    updates, _ = parse_key_file(src)

    assert updates["LLM_API_KEY"] == "sk-or-v1-x"
    assert updates["LLM_PROVIDER"] == "openrouter"
    assert "/" in updates["LLM_MODEL"]


def test_explicit_model_wins_over_openrouter_default(tmp_path):
    """Kullanıcı model yazdıysa (örn. ücretsiz model) takma ad onu ezmemeli."""
    from scripts.import_keys import parse_key_file

    src = tmp_path / "keys.txt"
    src.write_text(
        "LLM_MODEL=meta-llama/llama-3.3-70b-instruct:free\nOPENROUTER_API_KEY=sk-or-x\n",
        encoding="utf-8",
    )
    updates, _ = parse_key_file(src)

    assert updates["LLM_MODEL"] == "meta-llama/llama-3.3-70b-instruct:free"
    assert updates["LLM_PROVIDER"] == "openrouter"


def test_import_maps_aliases_to_env_keys(tmp_path):
    """ANTHROPIC_API_KEY → LLM_API_KEY + LLM_PROVIDER=anthropic."""
    from scripts.import_keys import parse_key_file

    src = tmp_path / "keys.txt"
    src.write_text(
        "ANTHROPIC_API_KEY=sk-ant-x\nPINATA_JWT=eyJ.x\nCHAINALYSIS_API_KEY=ca-x\n",
        encoding="utf-8",
    )
    updates, warnings = parse_key_file(src)

    assert warnings == []
    assert updates == {
        "LLM_API_KEY": "sk-ant-x",
        "LLM_PROVIDER": "anthropic",
        "PINATA_JWT": "eyJ.x",
        "SCREENING_API_KEY": "ca-x",
        "SCREENING_PROVIDER": "chainalysis",
    }


def test_import_skips_empty_and_unknown_lines(tmp_path):
    """Boş bırakılan satır .env'yi ezmemeli; bilinmeyen ad uyarı üretmeli."""
    from scripts.import_keys import parse_key_file

    src = tmp_path / "keys.txt"
    src.write_text(
        "# yorum\nANTHROPIC_API_KEY=\nBOGUS=x\nnoequals\nPINATA_JWT=jwt\n", encoding="utf-8"
    )
    updates, warnings = parse_key_file(src)

    assert updates == {"PINATA_JWT": "jwt"}
    assert len(warnings) == 2


def test_import_respects_explicit_provider(tmp_path):
    """Kullanıcı sağlayıcıyı açıkça yazdıysa takma ad onu ezmemeli."""
    from scripts.import_keys import parse_key_file

    src = tmp_path / "keys.txt"
    src.write_text(
        "LLM_PROVIDER=openai\nANTHROPIC_API_KEY=sk-x\n", encoding="utf-8"
    )
    updates, _ = parse_key_file(src)

    assert updates["LLM_PROVIDER"] == "openai"


def test_import_strips_quotes(tmp_path):
    from scripts.import_keys import parse_key_file

    src = tmp_path / "keys.txt"
    src.write_text('PINATA_JWT="quoted-jwt"\n', encoding="utf-8")
    updates, _ = parse_key_file(src)

    assert updates["PINATA_JWT"] == "quoted-jwt"
