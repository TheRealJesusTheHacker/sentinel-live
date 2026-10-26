"""Premium welcome splash pins (2026-10-26).

The splash is the public homepage's front-door moment only: the real
Sentinel Safeguard logo and WELCOME, shown once per browser session,
with interaction skip, an animation-independent fallback, reduced
motion treatment, and no ability to block a visitor when JavaScript
is unavailable. These pins intentionally inspect the static homepage
source as shipped and the homepage as rendered; every other public
surface must stay splash-free.
"""
import importlib.util
import re
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent
HOME = SRC / "site" / "index.html"
LOGO = "/assets/sentinel-safeguard-logo.jpg"


def _home() -> str:
    return HOME.read_text(encoding="utf-8")


def _splash_block(html: str) -> str:
    start = html.index('id="sentinel-splash"')
    end = html.index('<div class="page">', start)
    return html[start:end]


def _load_app(tmp: Path, name: str):
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    for item in ("templates", "static", "insights", "site"):
        if (SRC / item).is_dir():
            shutil.copytree(SRC / item, tmp / item)
    (tmp / "config.yaml").write_text("server:\n  port: 8443\n",
                                     encoding="utf-8")
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
    tmp = tmp_path_factory.mktemp("sl-splash")
    return _load_app(tmp, "sl_app_splash")


def test_homepage_has_one_splash_with_the_real_logo_and_welcome():
    html = _home()
    assert html.count('id="sentinel-splash"') == 1
    splash = _splash_block(html)
    assert splash.count(f'src="{LOGO}"') == 4  # base + three slices
    assert 'data-text="WELCOME"' in splash
    assert "".join(re.findall(r"<span[^>]*>([A-Z])</span>", splash)) == "WELCOME"
    assert (SRC / "site" / "assets" / "sentinel-safeguard-logo.jpg").is_file()


def test_splash_is_only_in_the_static_homepage_source():
    assert 'id="sentinel-splash"' in _home()
    for rel in ("site/report-issue/index.html", "site/ticket/index.html",
                "templates/base.html", "templates/index.html"):
        assert 'id="sentinel-splash"' not in (
            SRC / rel).read_text(encoding="utf-8"), rel


@pytest.mark.parametrize("path", ["/", "/index.html"])
def test_rendered_homepage_routes_carry_the_splash_once(app_mod, path):
    resp = TestClient(app_mod.app, raise_server_exceptions=False).get(path)
    assert resp.status_code == 200
    assert resp.text.count('id="sentinel-splash"') == 1
    assert LOGO in _splash_block(resp.text)


@pytest.mark.parametrize("path", ["/report-issue", "/ticket", "/operations",
                                  "/contact", "/sentinel-news"])
def test_other_public_surfaces_do_not_carry_the_splash(app_mod, path):
    resp = TestClient(app_mod.app, raise_server_exceptions=False).get(path)
    assert resp.status_code == 200, path
    assert 'id="sentinel-splash"' not in resp.text, path


def test_splash_precedes_the_page_and_is_hidden_without_javascript():
    html = _home()
    assert html.index('id="sentinel-splash"') < html.index('<div class="page">')
    assert re.search(r'id="sentinel-splash"[^>]*\bhidden\b', html)
    assert ".sentinel-splash[hidden]{display:none!important}" in html


def test_once_per_session_skip_and_fallback_logic_are_present():
    html = _home()
    for token in (
        "window.sessionStorage.getItem(storageKey)",
        "window.sessionStorage.setItem(storageKey,'1')",
        "splash.addEventListener('pointerdown',dismiss",
        "splash.addEventListener('click',dismiss)",
        "window.addEventListener('keydown',dismiss,true)",
        "dismissTimer=window.setTimeout(dismiss,reduced?620:1740)",
        "hardTimer=window.setTimeout(removeSplash,reduced?1250:2600)",
        "},3400);",
    ):
        assert token in html, token


def test_scroll_lock_is_applied_and_removed_by_the_controller():
    html = _home()
    assert "html.splash-lock,body.splash-lock{overflow:hidden!important" in html
    assert "root.classList.add('splash-lock')" in html
    assert "root.classList.remove('splash-lock')" in html
    assert "document.documentElement.classList.remove('splash-lock')" in html


def test_reduced_motion_gets_a_clean_static_splash():
    html = _home()
    reduced = html[html.index("@media(prefers-reduced-motion:reduce){.sentinel-splash"):]
    assert ".sentinel-splash__slice" in reduced
    assert "display:none!important" in reduced
    assert "animation:none!important" in reduced
    assert "window.matchMedia('(prefers-reduced-motion: reduce)').matches" in html


def test_animation_sequence_is_layered_and_transform_opacity_only():
    html = _home()
    for name in ("splashScan", "splashLogoResolve", "splashSliceOne",
                 "splashSliceTwo", "splashSliceThree", "splashLetterIn",
                 "splashWordGhost", "splashTrace"):
        assert f"@keyframes {name}" in html, name
    splash_css = html[html.index("Premium welcome splash"):html.index("</style>")]
    # The glitch layers animate transform/opacity; no width/height/top/
    # left keyframe layout work sneaks into the premium sequence.
    keyframes = "".join(re.findall(r"@keyframes[^{]+\{(.*?)\}\s*(?=@keyframes|@media|\s*</style>)",
                                   splash_css, flags=re.S))
    assert "width:" not in keyframes
    assert "height:" not in keyframes


def test_splash_stays_inside_the_black_emerald_white_system():
    html = _home()
    splash_css = html[html.index("Premium welcome splash"):html.index("</style>")]
    assert "#060806" in splash_css
    assert "#00e676" in splash_css
    assert "#eafff3" in splash_css
    for forbidden in ("purple", "violet", "magenta", "fuchsia", "rainbow",
                      "rgb(255,0", "rgb(0,0,255", "#ff0000", "#0000ff"):
        assert forbidden not in splash_css.lower(), forbidden


def test_homepage_nav_still_places_sentinel_news_after_insights(app_mod):
    resp = TestClient(app_mod.app, raise_server_exceptions=False).get("/")
    assert resp.status_code == 200
    assert resp.text.index('href="/insights"') < resp.text.index(
        'href="/sentinel-news"')
