"""Sweep #6 CodeQL regression: secret-bearing config values are
never written to the log (py/clear-text-logging-sensitive-data).

The config normalizer rejects non-string values for secret-bearing
keys (turnstile.secret_key, flight_api.api_key,
threat_feeds.abuse_ch_auth_key, briefing_token, admin_key). It used
to log the rejected value with %r; a malformed-but-real secret
(e.g. a YAML mapping pasted where a string belongs) would land in
the log file in clear text. The warning now logs only the type.
This test loads the real app with sentinel-marked malformed
secrets and asserts the sentinels appear nowhere in the log output
while normalization still restores the empty defaults.
"""
import importlib.util
import shutil
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent

SENTINEL = "SENTINEL-SECRET-DO-NOT-LOG-7f3a"

CONFIG = (
    # List values reach the normalizer (a mapping value is dropped
    # earlier by the merge guard, which already warns type-only);
    # a one-item list is exactly how a real secret could be pasted
    # in YAML and would previously have been logged verbatim.
    "turnstile:\n"
    "  enabled: false\n"
    f"  secret_key: [\"{SENTINEL}\"]\n"
    "flight_api:\n"
    f"  api_key: [\"{SENTINEL}\"]\n"
    "threat_feeds:\n"
    f"  abuse_ch_auth_key: [\"{SENTINEL}\"]\n"
    f"briefing_token: [\"{SENTINEL}\"]\n"
    f"admin_key: [\"{SENTINEL}\"]\n"
)


def _load_app(tmp: Path, name: str):
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    shutil.copytree(SRC / "templates", tmp / "templates")
    shutil.copytree(SRC / "static", tmp / "static")
    (tmp / "config.yaml").write_text(CONFIG, encoding="utf-8")

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


def test_malformed_secrets_normalized_and_never_logged(tmp_path):
    mod = _load_app(tmp_path, "sl_app_sweep6_codeql")
    # Normalization still happens (functionality preserved).
    assert mod.config["turnstile"]["secret_key"] == ""
    assert mod.config["flight_api"]["api_key"] == ""
    assert mod.config["threat_feeds"]["abuse_ch_auth_key"] == ""
    assert mod.config["briefing_token"] == ""
    assert mod.config["admin_key"] == ""
    # Flush every handler, then scan all log output in the app dir.
    for handler in mod.log.handlers:
        handler.flush()
    logged = ""
    for path in tmp_path.rglob("*"):
        if path.is_file() and path.suffix in (".log", ".txt"):
            logged += path.read_text(encoding="utf-8", errors="replace")
    assert "turnstile.secret_key invalid (type list)" in logged
    assert SENTINEL not in logged
