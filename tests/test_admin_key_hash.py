"""Admin-key hash storage pins (REMEDIATION 5a, 2026-10-26).

The admin key is stored in config ONLY as its SHA-256 hex digest
(`admin_key_sha256`); the presented key is hashed and the digests are
compared with hmac.compare_digest. These pins cover:

  * the correct key authenticates against a hash-only config, on the
    admin page and the admin API, with the unchanged response shape;
  * a wrong key, no key, and a non-ASCII key are rejected with the
    exact pre-change contract (403, {"detail": "Admin access denied."});
  * a tampered hash (one hex char flipped) rejects the correct key,
    and a malformed hash (not 64 hex chars) fails closed at startup;
  * the documented transition: a legacy plaintext `admin_key` still
    authenticates while no hash is set, and the hash takes precedence
    when both are present;
  * the constant-time digest comparison is present in the source of
    require_admin (code-inspection pin, the suite's pattern for
    properties behavior alone cannot prove);
  * tools/hash_admin_key.py migrates a fixture config in place:
    correct digest, plaintext gone, other fields/comments intact,
    perms (600) preserved, timestamped 600 backup of the original,
    neither key nor digest printed, a second run a refused no-op,
    an existing empty hash line filled, and an ambiguous
    both-values config refused untouched.

Hermetic: scratch copies of the app, TestClient only, no network.
The fixture key below is a test value, not a real credential.
"""
import hashlib
import importlib.util
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent

KEY = "sekrit"
DIGEST = hashlib.sha256(KEY.encode("utf-8")).hexdigest()
TAMPERED = ("1" if DIGEST[0] != "1" else "2") + DIGEST[1:]

_tool_spec = importlib.util.spec_from_file_location(
    "hash_admin_key", SRC / "tools" / "hash_admin_key.py")
hash_tool = importlib.util.module_from_spec(_tool_spec)
_tool_spec.loader.exec_module(hash_tool)


def _load_app(tmp: Path, name: str, config_text: str):
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    shutil.copytree(SRC / "templates", tmp / "templates")
    shutil.copytree(SRC / "static", tmp / "static")
    site = tmp / "site"
    (site / "report-issue").mkdir(parents=True)
    (site / "ticket").mkdir(parents=True)
    (site / "index.html").write_text("<html>home</html>", encoding="utf-8")
    (site / "report-issue" / "index.html").write_text(
        "<html>report</html>", encoding="utf-8")
    (site / "ticket" / "index.html").write_text(
        "<html>ticket</html>", encoding="utf-8")
    (tmp / "config.yaml").write_text(config_text, encoding="utf-8")

    feeds_spec = importlib.util.spec_from_file_location(
        "feeds", tmp / "feeds.py")
    feeds_mod = importlib.util.module_from_spec(feeds_spec)
    sys.modules["feeds"] = feeds_mod
    feeds_spec.loader.exec_module(feeds_mod)

    spec = importlib.util.spec_from_file_location(name, tmp / "app.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _tunneled(extra: str) -> str:
    return extra + "tunnel:\n  enabled: true\n"


@pytest.fixture(scope="module")
def happ(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-adminhash")
    return _load_app(tmp, "sl_app_adminhash",
                     _tunneled(f'admin_key_sha256: "{DIGEST}"\n'))


@pytest.fixture(scope="module")
def tapp(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-adminhash-tampered")
    return _load_app(tmp, "sl_app_adminhash_tampered",
                     _tunneled(f'admin_key_sha256: "{TAMPERED}"\n'))


@pytest.fixture(scope="module")
def mapp(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-adminhash-malformed")
    return _load_app(tmp, "sl_app_adminhash_malformed",
                     _tunneled('admin_key_sha256: "not-a-digest"\n'))


@pytest.fixture(scope="module")
def lapp(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-adminhash-legacy")
    return _load_app(tmp, "sl_app_adminhash_legacy",
                     _tunneled(f'admin_key: "{KEY}"\n'))


@pytest.fixture(scope="module")
def bapp(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-adminhash-both")
    return _load_app(tmp, "sl_app_adminhash_both",
                     _tunneled(f'admin_key_sha256: "{DIGEST}"\n'
                               'admin_key: "some-other-key"\n'))


def _client(mod):
    return TestClient(mod.app, raise_server_exceptions=False,
                      client=("127.0.0.1", 50000))


# ------------------------------------------------------------ hash mode
def test_correct_key_authenticates_against_hash_only_config(happ):
    assert happ.config["admin_key_sha256"] == DIGEST
    assert not happ.config.get("admin_key")
    with _client(happ) as client:
        page = client.get("/admin", headers={"X-Admin-Key": KEY})
        assert page.status_code == 200
        api = client.get("/api/admin/submissions?type=tickets",
                         headers={"X-Admin-Key": KEY})
        assert api.status_code == 200


def test_wrong_key_rejected_against_hash_only_config(happ):
    with _client(happ) as client:
        resp = client.get("/admin", headers={"X-Admin-Key": "wrong"})
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Admin access denied."}
        resp = client.get("/admin")
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Admin access denied."}


def test_non_ascii_key_rejected_without_500(happ):
    # On the real wire this arrives as raw bytes >= 0x80 which the
    # server latin-1-decodes (the SL6-2 shape); httpx will only send
    # it as an explicit bytes value.
    raw = "sékrït-wröng".encode("latin-1")
    with _client(happ) as client:
        resp = client.get("/admin", headers={"X-Admin-Key": raw})
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Admin access denied."}


def test_tampered_hash_rejects_correct_key(tapp):
    assert tapp.config["admin_key_sha256"] == TAMPERED
    with _client(tapp) as client:
        resp = client.get("/admin", headers={"X-Admin-Key": KEY})
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Admin access denied."}


def test_malformed_hash_fails_closed(mapp):
    # Startup validation discards a non-digest hash value entirely…
    assert mapp.config["admin_key_sha256"] == ""
    # …so not even the would-be-correct key can authenticate.
    with _client(mapp) as client:
        resp = client.get("/admin", headers={"X-Admin-Key": KEY})
        assert resp.status_code == 403


# ------------------------------------------------------- transition mode
def test_legacy_plaintext_still_authenticates_during_transition(lapp):
    with _client(lapp) as client:
        resp = client.get("/admin", headers={"X-Admin-Key": KEY})
        assert resp.status_code == 200
        resp = client.get("/admin", headers={"X-Admin-Key": "wrong"})
        assert resp.status_code == 403


def test_hash_takes_precedence_over_plaintext_when_both_present(bapp):
    with _client(bapp) as client:
        resp = client.get("/admin", headers={"X-Admin-Key": KEY})
        assert resp.status_code == 200
        # the plaintext field's value no longer authenticates
        resp = client.get("/admin",
                          headers={"X-Admin-Key": "some-other-key"})
        assert resp.status_code == 403


# ------------------------------------------------------- comparison pin
def test_admin_compare_is_constant_time_over_hex_digests():
    src = (SRC / "app.py").read_text(encoding="utf-8")
    section = src.split("def require_admin", 1)[1].split(
        "# ------------------------------------------------------------------ background refresh", 1)[0]
    assert "hashlib.sha256" in section
    assert "hmac.compare_digest(presented," in section
    # the presented key is never compared against a stored value
    # directly, and digests are never compared with ==
    assert "compare_digest(key" not in section
    assert "presented ==" not in section


# ------------------------------------------------------- migration tool
FIXTURE_KEY = "sekrit-fixture-key"
FIXTURE_DIGEST = hashlib.sha256(
    FIXTURE_KEY.encode("utf-8")).hexdigest()
FIXTURE_CONFIG = (
    "# fixture comment that must survive\n"
    "server:\n"
    '  host: "127.0.0.1"\n'
    "  port: 8443\n"
    'briefing_token: "fixture-briefing-token"\n'
    f'admin_key: "{FIXTURE_KEY}"\n'
    "cors_origins: []\n"
    "nested:\n"
    '  admin_key: "nested-value-do-not-touch"\n'
)


def _write_fixture(tmp_path: Path, text: str = FIXTURE_CONFIG) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(text, encoding="utf-8")
    os.chmod(cfg, 0o600)
    return cfg


def test_migration_tool_converts_fixture_config(tmp_path, capsys):
    cfg = _write_fixture(tmp_path)
    assert hash_tool.migrate(cfg) == 0

    out = capsys.readouterr()
    assert FIXTURE_KEY not in out.out + out.err
    assert FIXTURE_DIGEST not in out.out + out.err

    text = cfg.read_text(encoding="utf-8")
    assert FIXTURE_KEY not in text
    parsed = yaml.safe_load(text)
    assert parsed["admin_key_sha256"] == FIXTURE_DIGEST
    assert "admin_key" not in parsed
    # every other field, the nested namesake, and the comment survive
    assert parsed["server"] == {"host": "127.0.0.1", "port": 8443}
    assert parsed["briefing_token"] == "fixture-briefing-token"
    assert parsed["nested"]["admin_key"] == "nested-value-do-not-touch"
    assert "# fixture comment that must survive" in text
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o600

    backups = list(tmp_path.glob("config.yaml.bak-*"))
    assert len(backups) == 1
    assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600
    assert backups[0].read_text(encoding="utf-8") == FIXTURE_CONFIG


def test_migration_tool_refuses_second_run(tmp_path):
    cfg = _write_fixture(tmp_path)
    assert hash_tool.migrate(cfg) == 0
    after_first = cfg.read_text(encoding="utf-8")
    assert hash_tool.migrate(cfg) == 2  # already migrated: refused
    assert cfg.read_text(encoding="utf-8") == after_first
    assert len(list(tmp_path.glob("config.yaml.bak-*"))) == 1


def test_migration_tool_fills_existing_empty_hash_line(tmp_path):
    cfg = _write_fixture(
        tmp_path,
        f'admin_key: "{FIXTURE_KEY}"\nadmin_key_sha256: ""\n')
    assert hash_tool.migrate(cfg) == 0
    text = cfg.read_text(encoding="utf-8")
    assert text.count("admin_key_sha256") == 1
    parsed = yaml.safe_load(text)
    assert parsed == {"admin_key_sha256": FIXTURE_DIGEST}


def test_migration_tool_refuses_ambiguous_both_values(tmp_path):
    original = (f'admin_key: "{FIXTURE_KEY}"\n'
                f'admin_key_sha256: "{FIXTURE_DIGEST}"\n')
    cfg = _write_fixture(tmp_path, original)
    assert hash_tool.migrate(cfg) == 2
    assert cfg.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob("config.yaml.bak-*")) == []
