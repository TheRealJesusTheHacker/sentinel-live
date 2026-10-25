"""Phase Two A pins (2026-10-25) — public-site polish + live previews.

Covers the Workstream A changes:
  * The operations landing carries live-preview panels for all three
    feeds (threat + geo panels fed by the public read APIs; the flight
    panel is the tracker search itself — it must never spend provider
    quota from the landing page).
  * The shared header gains an Operations link with correct
    active-page marking, keeps the public Library link, and bumps the
    stylesheet version query whenever style.css changes.
  * The flights page renders its legend + route note ABOVE the map
    and its live-position popup opens by default.
  * Invariants re-pinned alongside: the gated surfaces still refuse
    unauthenticated callers and the public pages stay public, and a
    token-less form POST under an active Turnstile config is rejected
    before anything is stored (fail-closed).

Loads app.py from a scratch copy the same way the other suites do.
Hermetic: no network — the data store is seeded directly.
"""
import importlib.util
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent


def _load_app(tmp: Path, name: str, config_text: str = "server:\n  port: 8443\n"):
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    shutil.copytree(SRC / "templates", tmp / "templates")
    shutil.copytree(SRC / "static", tmp / "static")
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


@pytest.fixture(scope="module")
def app_mod(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-phasetwo-a")
    return _load_app(tmp, "sl_app_phasetwo_a")


@pytest.fixture(scope="module")
def ts_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-phasetwo-a-ts")
    return _load_app(tmp, "sl_app_phasetwo_a_ts",
                     "turnstile:\n"
                     "  enabled: true\n"
                     '  secret_key: "test-secret"\n')


def _client(mod):
    return TestClient(mod.app, raise_server_exceptions=False)


# ------------------------------------------------------- live previews
def test_operations_has_three_live_preview_panels(app_mod):
    resp = _client(app_mod).get("/operations")
    assert resp.status_code == 200
    for marker in ('id="pv-threat-stat"', 'id="pv-threat-list"',
                   'id="pv-geo-stat"', 'id="pv-geo-list"',
                   'action="/flights"'):
        assert marker in resp.text, marker
    # one panel per feed, each click-through to its tracker
    assert resp.text.count('class="preview"') == 3
    for href in ('href="/threat-map"', 'href="/geopolitical"',
                 'href="/flights"'):
        assert href in resp.text


def test_operations_preview_script_uses_public_apis_only(app_mod):
    resp = _client(app_mod).get("/operations")
    assert "fetch('/api/threat-data')" in resp.text
    assert "fetch('/api/geo-data')" in resp.text
    assert "setInterval(pvLoad, 60000)" in resp.text
    # the landing never calls a flight-lookup surface (quota guard)
    assert "/api/flight" not in resp.text


# ------------------------------------------------------------- header
@pytest.mark.parametrize("path", ["/operations", "/threat-map",
                                  "/geopolitical", "/flights"])
def test_header_marks_current_page_and_keeps_library(app_mod, path):
    resp = _client(app_mod).get(path)
    assert resp.status_code == 200
    assert 'href="/operations"' in resp.text
    assert ('href="%s" class="active"' % path) in resp.text
    assert "https://command.sentinelsafeguard.net/library" in resp.text


def test_stylesheet_version_query_bumped(app_mod):
    resp = _client(app_mod).get("/operations")
    # 20261025-1 was Phase Two A's bump; the design pass changed
    # style.css again the same day and moved the query to -2 (the
    # standing rule: the version query follows EVERY CSS change);
    # -3 was the logo fix, -4 the Services page's section styles,
    # -5 the Who We Protect nav-band widening (1240px).
    # -6 is the How It Works nav-band widening (1720px).
    assert "/static/style.css?v=20261025-6" in resp.text


def test_header_uses_emblem_mark_not_full_poster(app_mod):
    # LOGOFIX-2026-10-25: the header slot is 44px tall; the full
    # portrait poster squeezed into it renders as an illegible dark
    # tile — effectively invisible on the dark headers (owner report,
    # browser-census proven). The header must use the derived emblem
    # lockup (assets/sentinel-safeguard-mark.jpg, served from the
    # site tree); the full poster stays on the homepage hero, the
    # social cards, and the Command sign-in screen.
    resp = _client(app_mod).get("/operations")
    assert resp.status_code == 200
    assert 'src="/assets/sentinel-safeguard-mark.jpg"' in resp.text
    assert 'class="brand-logo" src="/assets/sentinel-safeguard-logo.jpg"' not in resp.text


# ------------------------------------------------------------- flights
def test_flights_legend_and_note_above_map(app_mod):
    resp = _client(app_mod).get("/flights")
    assert resp.status_code == 200
    assert resp.text.index('id="fmap-note"') < resp.text.index('id="fmap"')
    assert "maplegend-top" in resp.text


def test_flights_live_popup_opens_by_default(app_mod):
    resp = _client(app_mod).get("/flights")
    assert ".addTo(fmap).openPopup()" in resp.text


# ---------------------------------------------------------- invariants
@pytest.mark.parametrize("path", ["/admin", "/news", "/status",
                                  "/health", "/api/news-data",
                                  "/api/admin/submissions"])
def test_gated_paths_still_refuse_unauthenticated(app_mod, path):
    # TestClient's host is "testclient", not loopback, and no admin
    # key is configured in this scratch config — the in-app gate must
    # refuse (403), never serve.
    resp = _client(app_mod).get(path)
    assert resp.status_code == 403, (path, resp.status_code)


@pytest.mark.parametrize("path", ["/operations", "/threat-map",
                                  "/geopolitical", "/flights"])
def test_public_pages_stay_public(app_mod, path):
    resp = _client(app_mod).get(path)
    assert resp.status_code == 200, (path, resp.status_code)


def test_tokenless_posts_rejected_when_turnstile_active(ts_app):
    client = _client(ts_app)
    contact = client.post("/api/contact", json={
        "name": "Pat", "email": "pat@example.co", "message": "hello"})
    assert contact.status_code == 400
    assert "bot check" in contact.json()["detail"]
    ticket = client.post("/api/ticket", json={
        "name": "Pat", "email": "pat@example.co",
        "subject": "help", "message": "hello"})
    assert ticket.status_code == 400
    assert "bot check" in ticket.json()["detail"]
