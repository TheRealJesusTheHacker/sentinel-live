"""Site polish pins (2026-10-25) — the themed browser 404.

A browser navigating to a missing page gets the site's own 404 in
the shared chrome; every other consumer keeps the app's plain JSON
error shape byte-for-byte in behavior:

  * no explicit text/html Accept (API clients, the suite default)
    -> JSON {"detail": "Not found."}, exactly as before;
  * /api/* paths -> JSON even WITH a browser Accept;
  * /internal/* -> JSON even WITH a browser Accept (the
    anti-probing surface answers one plain shape to everything);
  * non-404 errors (the admin gate's 403) -> JSON even WITH a
    browser Accept;
  * the themed page carries the canonical chrome and a real 404.
"""
import importlib.util
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent
BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}


def _load_app(tmp: Path, name: str):
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    shutil.copytree(SRC / "templates", tmp / "templates")
    shutil.copytree(SRC / "static", tmp / "static")
    if (SRC / "insights").is_dir():
        shutil.copytree(SRC / "insights", tmp / "insights")
    (tmp / "config.yaml").write_text("server:\n  port: 8443\n", encoding="utf-8")
    feeds_spec = importlib.util.spec_from_file_location("feeds", tmp / "feeds.py")
    feeds_mod = importlib.util.module_from_spec(feeds_spec)
    sys.modules["feeds"] = feeds_mod
    feeds_spec.loader.exec_module(feeds_mod)
    spec = importlib.util.spec_from_file_location(name, tmp / "app.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def app_mod(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-polish404")
    return _load_app(tmp, "sl_app_polish404")


def _client(mod):
    return TestClient(mod.app, raise_server_exceptions=False)


def test_browser_gets_themed_404(app_mod):
    resp = _client(app_mod).get("/no-such-page", headers=BROWSER)
    assert resp.status_code == 404
    assert "text/html" in resp.headers["content-type"]
    assert "Nothing" in resp.text and "answers here" in resp.text
    # the shared chrome — canonical nav travels with the error page
    assert 'href="/who-we-protect"' in resp.text
    assert 'href="/report-issue"' in resp.text


def test_browser_404_for_unknown_insight_slug(app_mod):
    resp = _client(app_mod).get("/insights/no-such-note", headers=BROWSER)
    assert resp.status_code == 404
    assert "text/html" in resp.headers["content-type"]


def test_default_accept_keeps_plain_json_404(app_mod):
    client = _client(app_mod)
    # Both pre-existing shapes survive byte-for-byte: the router's
    # own 404 ("Not Found") for unmatched paths, and the app's raised
    # 404 ("Not found.") for matched routes that raise it.
    resp = client.get("/no-such-page")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Not Found"}
    resp = client.get("/insights/no-such-note")
    assert resp.json() == {"detail": "Not found."}


def test_api_and_internal_stay_json_for_browsers(app_mod):
    client = _client(app_mod)
    resp = client.get("/api/does-not-exist", headers=BROWSER)
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Not Found"}
    resp = client.get("/internal/visitors", headers=BROWSER)
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Not found."}


def test_gate_403_stays_json_for_browsers(app_mod):
    resp = _client(app_mod).get("/admin", headers=BROWSER)
    assert resp.status_code == 403
    assert resp.json() == {"detail": "Admin access denied."}
