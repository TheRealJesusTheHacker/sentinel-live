"""Front-door routing tests (owner order 2026-10-23).

The marketing homepage is the front door: when the static site is
present (site/index.html next to app.py), GET / serves that file's
exact bytes — the same bytes GET /index.html serves via the static
mount. The Live Operations landing keeps its own home at /operations.
Without a site dir (e.g. the packaged server build), GET / falls back
to the operations landing instead of 404ing.

Loads app.py from a scratch copy the same way
test_hackproof_proxy.py does, with and without a seeded site dir.
"""
import importlib.util
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent

SITE_HOME = (b"<!DOCTYPE html><html><head>"
             b"<title>Sentinel Safeguard LLC - Cybersecurity &amp; IT</title>"
             b"</head><body>MARKETING HOMEPAGE MARKER</body></html>")


def _load_app(tmp: Path, name: str, with_site: bool):
    """Import app.py (and its feeds.py) from a scratch dir holding a
    minimal config.yaml, optionally with site/index.html in place
    BEFORE import (the static mount and the / handler both key off
    the site dir existing next to app.py)."""
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    shutil.copytree(SRC / "templates", tmp / "templates")
    shutil.copytree(SRC / "static", tmp / "static")
    (tmp / "config.yaml").write_text("server:\n  port: 8443\n",
                                      encoding="utf-8")
    if with_site:
        (tmp / "site").mkdir()
        (tmp / "site" / "index.html").write_bytes(SITE_HOME)

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


@pytest.fixture(scope="module")
def site_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-frontdoor-site")
    return _load_app(tmp, "sl_app_frontdoor_site", with_site=True)


@pytest.fixture(scope="module")
def nosite_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-frontdoor-nosite")
    return _load_app(tmp, "sl_app_frontdoor_nosite", with_site=False)


def test_root_serves_marketing_homepage_when_site_present(site_app):
    client = TestClient(site_app.app, raise_server_exceptions=False)
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.content == SITE_HOME


def test_index_html_still_serves_homepage(site_app):
    client = TestClient(site_app.app, raise_server_exceptions=False)
    resp = client.get("/index.html")
    assert resp.status_code == 200
    assert resp.content == SITE_HOME


def test_operations_landing_moved_not_deleted(site_app):
    client = TestClient(site_app.app, raise_server_exceptions=False)
    resp = client.get("/operations")
    assert resp.status_code == 200
    assert "Live Operations" in resp.text


def test_root_falls_back_to_operations_without_site(nosite_app):
    client = TestClient(nosite_app.app, raise_server_exceptions=False)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Live Operations" in resp.text
    resp = client.get("/operations")
    assert resp.status_code == 200
    assert "Live Operations" in resp.text
