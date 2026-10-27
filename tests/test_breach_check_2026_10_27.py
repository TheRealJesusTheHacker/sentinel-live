"""Breach Check pins (BREACH-CHECK-2026-10-27, owner order
2026-10-27) — Sentinel's own public "Breach Check" page
(/breach-check) with its two tools:

  * Tool 1, email breach lookup: POST /api/breach-check/email
    proxies XposedOrNot's check-email API server-side and joins
    the returned breach names against a cached copy of
    XposedOrNot's /v1/breaches metadata corpus.
  * Tool 2, password exposure check: the browser SHA-1 hashes the
    password locally (crypto.subtle) and sends ONLY the first 5
    hex characters; POST /api/breach-check/password proxies the
    Pwned Passwords range API and returns the suffix list for the
    browser to match locally.

Hermetic: every upstream seam (app._breach_upstream_*) is
monkeypatched with real-shaped payloads — the suite never hits
the network, mirroring the feeds monkeypatch style elsewhere.

Privacy pins are the point of this file: a canary address and a
canary prefix must appear in NO log output and NO file under the
app's data dir after a lookup, and the error paths must answer
with fixed strings (an upstream exception can embed the request
URL — and the email leg's URL carries the searched address).
"""
import importlib.util
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent


def _load_app(tmp: Path, name: str, config_text: str):
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    for item in ("templates", "static", "insights", "site"):
        if (SRC / item).is_dir():
            shutil.copytree(SRC / item, tmp / item)
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
    tmp = tmp_path_factory.mktemp("sl-breach-check")
    return _load_app(tmp, "sl_app_breach_check",
                     "server:\n  port: 8443\n")


@pytest.fixture(scope="module")
def ts_mod(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-breach-check-ts")
    return _load_app(tmp, "sl_app_breach_check_ts",
                     "turnstile:\n  enabled: true\n"
                     "  secret_key: \"test-secret-not-real\"\n")


def _client(mod, ip):
    return TestClient(mod.app, raise_server_exceptions=False,
                      client=(ip, 50000))


def _reset_caches(mod, monkeypatch):
    monkeypatch.setattr(mod, "_breach_corpus_cache",
                        {"at": 0.0, "ok": False, "by_name": {}})
    monkeypatch.setattr(mod, "_breach_range_cache", {})


# Real-shaped XposedOrNot payloads (field names verified live
# 2026-10-27): check-email nests the names one list deep, and the
# corpus carries breachID / breachedDate / domain / exposedData /
# passwordRisk / exposedRecords.
_CORPUS = {"status": "success", "exposedBreaches": [
    {"breachID": "Adobe", "breachedDate": "2013-10-03T00:00:00+00:00",
     "addedDate": "2013-12-04T00:00:00+00:00", "domain": "adobe.com",
     "industry": "Software", "passwordRisk": "easytocrack",
     "exposedData": ["Email addresses", "Password hints",
                     "Passwords", "Usernames"],
     "exposedRecords": 152445165,
     "exposureDescription": "fixture"},
    {"breachID": "NoDataTypes",
     "breachedDate": "2021-05-01T00:00:00+00:00",
     "addedDate": "2021-06-01T00:00:00+00:00", "domain": "example.net",
     "industry": "Retail", "passwordRisk": "unknown",
     "exposedData": [], "exposedRecords": 42,
     "exposureDescription": "fixture"},
]}
_FOUND = {"breaches": [["Adobe", "NoDataTypes", "MysteryBreach"]],
          "email": "someone@example.com", "status": "success"}
_RANGE_TEXT = (
    "003CD215739D7C1B2218670D26F81408237:2\n"
    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3303003\n"
    "not-a-suffix-line\n"
    "ABC:12\n"
    "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:9\n")


def _stub_found(mod, monkeypatch, corpus=_CORPUS):
    _reset_caches(mod, monkeypatch)
    calls = {"check": 0, "corpus": 0, "range": 0}

    async def fake_check(email):
        calls["check"] += 1
        return _FOUND

    async def fake_corpus():
        calls["corpus"] += 1
        return corpus

    monkeypatch.setattr(mod, "_breach_upstream_check_email", fake_check)
    monkeypatch.setattr(mod, "_breach_upstream_breaches", fake_corpus)
    return calls


# ------------------------------------------------------------ parsers
def test_check_names_double_nested_and_not_found(app_mod):
    assert app_mod._breach_check_names(_FOUND) == [
        "Adobe", "NoDataTypes", "MysteryBreach"]
    assert app_mod._breach_check_names(
        {"Error": "Not found", "email": None}) == []
    assert app_mod._breach_check_names({"unexpected": 1}) is None
    assert app_mod._breach_check_names(["Adobe"]) is None
    assert app_mod._breach_check_names({"breaches": "Adobe"}) is None


def test_corpus_parse_uses_real_fields(app_mod):
    by_name = app_mod._breach_corpus_parse(_CORPUS)
    assert by_name["Adobe"] == {
        "name": "Adobe", "date": "2013-10-03", "domain": "adobe.com",
        "exposed_data": ["Email addresses", "Password hints",
                         "Passwords", "Usernames"],
        "password_risk": "easytocrack", "exposed_records": 152445165}
    assert by_name["NoDataTypes"]["exposed_data"] == []
    assert app_mod._breach_corpus_parse({"nope": []}) is None
    assert app_mod._breach_corpus_parse([]) is None


def test_range_parse_defensive(app_mod):
    out = app_mod._breach_range_parse(_RANGE_TEXT)
    assert out == ["003CD215739D7C1B2218670D26F81408237:2",
                   "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3303003"]
    assert app_mod._breach_range_parse("") is None
    assert app_mod._breach_range_parse("garbage only") is None


# ------------------------------------------------------------ email leg
def test_email_found_joins_corpus_cards(app_mod, monkeypatch):
    _stub_found(app_mod, monkeypatch)
    r = _client(app_mod, "10.9.1.1").post(
        "/api/breach-check/email", json={"email": "someone@example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["found"] is True
    assert body["metadata_available"] is True
    # the searched address is never echoed back
    assert "someone@example.com" not in r.text
    cards = body["breaches"]
    assert [c["name"] for c in cards] == [
        "Adobe", "NoDataTypes", "MysteryBreach"]
    adobe = cards[0]
    assert adobe["date"] == "2013-10-03"
    assert adobe["domain"] == "adobe.com"
    assert adobe["exposed_data"] == [
        "Email addresses", "Password hints", "Passwords", "Usernames"]
    assert adobe["password_risk"] == "easytocrack"
    assert adobe["exposed_records"] == 152445165
    assert adobe["metadata"] is True
    # a breach whose corpus entry publishes no data types keeps an
    # empty list (the card says they weren't published — the JS
    # pin below), never an invented one
    assert cards[1]["metadata"] is True
    assert cards[1]["exposed_data"] == []
    # a breach missing from the corpus falls back to name-only
    mystery = cards[2]
    assert mystery == {"name": "MysteryBreach", "date": "",
                       "domain": "", "exposed_data": [],
                       "password_risk": "", "exposed_records": None,
                       "metadata": False}
    assert r.headers.get("cache-control") == "no-store"


def test_email_not_found_is_clean_state(app_mod, monkeypatch):
    _reset_caches(app_mod, monkeypatch)

    async def fake_check(email):
        return {"Error": "Not found", "email": None}

    monkeypatch.setattr(app_mod, "_breach_upstream_check_email",
                        fake_check)
    r = _client(app_mod, "10.9.1.2").post(
        "/api/breach-check/email", json={"email": "clean@example.com"})
    assert r.status_code == 200
    assert r.json() == {"ok": True, "found": False, "breaches": [],
                        "metadata_available": True}


def test_email_upstream_down_is_unavailable_not_clean(app_mod,
                                                       monkeypatch):
    _reset_caches(app_mod, monkeypatch)

    async def dead_check(email):
        # the exception text deliberately embeds the searched
        # address, the way an httpx error embeds its URL — the
        # handler's answer (and log line) must not repeat it
        raise ConnectionError("boom for someone@example.com")

    monkeypatch.setattr(app_mod, "_breach_upstream_check_email",
                        dead_check)
    r = _client(app_mod, "10.9.1.3").post(
        "/api/breach-check/email", json={"email": "someone@example.com"})
    assert r.status_code == 503
    assert "unavailable" in r.json()["detail"]
    assert "someone@example.com" not in r.text

    async def weird_check(email):
        return {"totally": "unexpected"}

    monkeypatch.setattr(app_mod, "_breach_upstream_check_email",
                        weird_check)
    r = _client(app_mod, "10.9.1.3").post(
        "/api/breach-check/email", json={"email": "someone@example.com"})
    assert r.status_code == 503  # malformed upstream is NOT "clean"


def test_email_metadata_corpus_down_degrades_to_name_only(app_mod,
                                                          monkeypatch):
    _reset_caches(app_mod, monkeypatch)

    async def fake_check(email):
        return _FOUND

    async def dead_corpus():
        raise ConnectionError("corpus down")

    monkeypatch.setattr(app_mod, "_breach_upstream_check_email",
                        fake_check)
    monkeypatch.setattr(app_mod, "_breach_upstream_breaches",
                        dead_corpus)
    r = _client(app_mod, "10.9.1.4").post(
        "/api/breach-check/email", json={"email": "someone@example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["found"] is True
    assert body["metadata_available"] is False
    assert all(c["metadata"] is False for c in body["breaches"])
    assert [c["name"] for c in body["breaches"]] == [
        "Adobe", "NoDataTypes", "MysteryBreach"]


def test_corpus_is_cached_across_lookups(app_mod, monkeypatch):
    calls = _stub_found(app_mod, monkeypatch)
    client = _client(app_mod, "10.9.1.5")
    for _ in range(2):
        r = client.post("/api/breach-check/email",
                        json={"email": "someone@example.com"})
        assert r.status_code == 200
    assert calls["check"] == 2  # the lookup itself is always live
    assert calls["corpus"] == 1  # the corpus is fetched at most / TTL


@pytest.mark.parametrize("bad", ["not-an-email", "a@b", "a b@c.com",
                                 "@example.com", "a@example", ""])
def test_email_shape_validated_before_upstream(app_mod, monkeypatch,
                                               bad):
    calls = _stub_found(app_mod, monkeypatch)
    r = _client(app_mod, "10.9.1.6").post(
        "/api/breach-check/email", json={"email": bad})
    assert r.status_code == 400
    assert calls["check"] == 0


# --------------------------------------------------------- password leg
def _stub_range(mod, monkeypatch):
    _reset_caches(mod, monkeypatch)
    calls = {"range": 0}

    async def fake_range(prefix):
        calls["range"] += 1
        assert prefix == "5BAA6"
        return _RANGE_TEXT

    monkeypatch.setattr(mod, "_breach_upstream_range", fake_range)
    return calls


def test_password_range_passthrough_shape(app_mod, monkeypatch):
    _stub_range(app_mod, monkeypatch)
    r = _client(app_mod, "10.9.2.1").post(
        "/api/breach-check/password", json={"prefix": "5BAA6"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["prefix"] == "5BAA6"
    # only well-formed suffix:count lines ride back — the browser
    # matches its own suffix against exactly this list
    assert body["suffixes"] == [
        "003CD215739D7C1B2218670D26F81408237:2",
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3303003"]
    assert r.headers.get("cache-control") == "no-store"


def test_password_range_is_cached_per_prefix(app_mod, monkeypatch):
    calls = _stub_range(app_mod, monkeypatch)
    client = _client(app_mod, "10.9.2.2")
    for _ in range(2):
        r = client.post("/api/breach-check/password",
                        json={"prefix": "5BAA6"})
        assert r.status_code == 200
    assert calls["range"] == 1


@pytest.mark.parametrize("bad", ["5baa6", "5BAA", "5BAA66", "ZZZZZ",
                                 "5BAA ", "", "5B-AA"])
def test_password_prefix_shape_refused(app_mod, monkeypatch, bad):
    calls = _stub_range(app_mod, monkeypatch)
    r = _client(app_mod, "10.9.2.3").post(
        "/api/breach-check/password", json={"prefix": bad})
    assert r.status_code == 400
    assert calls["range"] == 0


def test_password_prefix_non_string_refused(app_mod, monkeypatch):
    calls = _stub_range(app_mod, monkeypatch)
    r = _client(app_mod, "10.9.2.4").post(
        "/api/breach-check/password", json={"prefix": 12345})
    assert r.status_code == 400
    assert calls["range"] == 0


def test_password_upstream_down_is_unavailable(app_mod, monkeypatch):
    _reset_caches(app_mod, monkeypatch)

    async def dead_range(prefix):
        raise ConnectionError("range down")

    monkeypatch.setattr(app_mod, "_breach_upstream_range", dead_range)
    r = _client(app_mod, "10.9.2.5").post(
        "/api/breach-check/password", json={"prefix": "ABCDE"})
    assert r.status_code == 503
    assert "unavailable" in r.json()["detail"]


# ------------------------------------------------------- cross-cutting
@pytest.mark.parametrize("path", ["/api/breach-check/email",
                                  "/api/breach-check/password"])
def test_api_routes_are_post_only(app_mod, path):
    r = _client(app_mod, "10.9.3.1").get(path)
    assert r.status_code == 405


def test_rate_limit_caps_breach_endpoints(app_mod, monkeypatch):
    _stub_range(app_mod, monkeypatch)
    client = _client(app_mod, "10.9.3.2")
    codes = [client.post("/api/breach-check/password",
                         json={"prefix": "5BAA6"}).status_code
             for _ in range(21)]
    assert codes[:20] == [200] * 20
    assert codes[20] == 429  # the shared form limiter (20 / 10 min)


def test_privacy_canary_appears_nowhere(app_mod, monkeypatch):
    _stub_found(app_mod, monkeypatch)
    _stub_range(app_mod, monkeypatch)
    canary_email = "canary-7f3a-breach@example.com"
    canary_prefix = "C0DE5"
    client = _client(app_mod, "10.9.3.3")
    r = client.post("/api/breach-check/email",
                    json={"email": canary_email})
    assert r.status_code == 200

    async def fake_range(prefix):
        return _RANGE_TEXT

    monkeypatch.setattr(app_mod, "_breach_upstream_range", fake_range)
    r = client.post("/api/breach-check/password",
                    json={"prefix": canary_prefix})
    assert r.status_code == 200
    for handler in app_mod.log.handlers:
        handler.flush()
    root = app_mod.DATA_DIR.parent
    offenders = []
    for path in root.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        data = path.read_bytes()
        if canary_email.encode() in data or canary_prefix.encode() in data:
            offenders.append(str(path))
    assert offenders == []


def test_turnstile_gates_both_endpoints(ts_mod, monkeypatch):
    calls = _stub_found(ts_mod, monkeypatch)
    _stub_range(ts_mod, monkeypatch)

    async def reject(secret, token, remoteip):
        return {"success": False, "error-codes": ["invalid-input"]}

    monkeypatch.setattr(ts_mod, "_turnstile_siteverify", reject)
    client = _client(ts_mod, "10.9.4.1")
    # missing token -> 400 on BOTH legs, upstream never touched
    for path, payload in (
            ("/api/breach-check/email", {"email": "someone@example.com"}),
            ("/api/breach-check/password", {"prefix": "5BAA6"})):
        r = client.post(path, json=payload)
        assert r.status_code == 400, path
        assert "bot check" in r.json()["detail"].lower()
    assert calls["check"] == 0

    async def accept(secret, token, remoteip):
        assert token == "real-token-breach"
        return {"success": True, "hostname": "sentinelsafeguard.net"}

    monkeypatch.setattr(ts_mod, "_turnstile_siteverify", accept)
    client = _client(ts_mod, "10.9.4.2")
    r = client.post("/api/breach-check/email", json={
        "email": "someone@example.com",
        "cf-turnstile-response": "real-token-breach"})
    assert r.status_code == 200 and r.json()["found"] is True
    r = client.post("/api/breach-check/password", json={
        "prefix": "5BAA6", "cf-turnstile-response": "real-token-breach"})
    assert r.status_code == 200 and r.json()["suffixes"]


# ------------------------------------------------------------------ page
def _flat(html_text: str) -> str:
    return " ".join(html_text.split())


def test_page_renders_both_tools_and_disclosures(app_mod):
    r = _client(app_mod, "10.9.5.1").get("/breach-check")
    assert r.status_code == 200
    body = _flat(r.text)
    for marker in (
        "<title>Breach Check",
        'property="og:title" content="Breach Check — Sentinel Safeguard"',
        'id="bc-email-form"', 'id="bc-email"', 'id="bc-email-submit"',
        'id="bc-email-results"',
        'id="bc-password-form"', 'id="bc-password"',
        'id="bc-password-submit"', 'id="bc-password-results"',
        'id="what-to-do"', 'id="how-it-works"',
        # named sources, stated plainly
        "XposedOrNot", "Have I Been Pwned", "Pwned Passwords",
        # Sentinel's own name — and not the HIBP site's name
        "it is not the Have I Been Pwned website",
        # the password promise, plainly
        "Your full password and its full hash are never transmitted or stored.",
        "only the first 5 characters of that fingerprint are sent",
        # the storage promise
        "We never store a searched email address",
        "not in a database, not in a file, not in a log",
        # what-to-do block
        "Change that password everywhere it is reused.",
        "multi-factor authentication (MFA)",
        "Consider a credit freeze",
        # the standard reader CTA
        "Worried something like this could hit your business?",
        # wiring: turnstile + the page's own script, nothing inline
        "https://challenges.cloudflare.com/turnstile/v0/api.js",
        "/static/js/breach-check.js",
        "/static/style.css?v=20261027-5",
    ):
        assert marker in body, marker
    # one Turnstile widget per form, same public sitekey as /contact
    assert body.count('data-sitekey="0x4AAAAAAFiiv8HgOgu4CceoE"') == 2
    # the nav marks Breach Check active on its own page
    assert 'href="/breach-check" class="active"' in r.text
    assert "Liberty" not in body


def test_page_in_sitemap_and_visitor_sets(app_mod):
    assert "/breach-check" in app_mod._SITEMAP_PATHS
    assert "/breach-check" in app_mod._VISITOR_PUBLIC_PATHS
    assert app_mod._visitor_is_public("/breach-check")
    r = _client(app_mod, "10.9.5.2").get("/sitemap.xml")
    assert r.status_code == 200
    assert "https://sentinelsafeguard.net/breach-check" in r.text


def test_js_hashes_locally_and_sends_only_the_prefix():
    js = (SRC / "static" / "js" / "breach-check.js").read_text(
        encoding="utf-8")
    for snippet in (
        "crypto.subtle.digest('SHA-1'",
        "hash.slice(0, 5)",       # the prefix is all that is sent
        "hash.slice(5)",          # the suffix stays in the browser
        "prefix: prefix",
        "'cf-turnstile-response'",
        "/api/breach-check/email",
        "/api/breach-check/password",
        "textContent",            # upstream strings render as text
        "createElement",
        "Source: XposedOrNot",
        "Data types weren",
        "has appeared about",
        "times in breach corpora",
        "was not found in the breach corpora",
    ):
        assert snippet in js, snippet
    # the full hash and the password itself are never payload keys
    assert "innerHTML" not in js
    assert "hash: hash" not in js
    assert "password: password" not in js
    assert "email: email" in js  # the email leg's one disclosed send
