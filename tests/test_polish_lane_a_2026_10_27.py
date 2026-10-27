"""POLISH-LANE-A-2026-10-27 pins.

- The bottom navigation block is gone from every public surface: the
  footer carries only the slim legal nav (Privacy, Disclosure), the
  copyright/entity line, and the verified social icon row.
- Social URLs are exactly the profiles verified live on 2026-10-27:
  the Facebook Page (connector: "Sentinel Safeguard LLC.", profile_id
  61554735587784), Instagram @jesusthehacker (website field points at
  sentinelsafeguard.net), and GitHub TheRealJesusTheHacker. No
  Telegram (owner ordered it off 2026-10-25), no @freyasig (personal).
- Server-rendered timestamps use the ct_time house format
  (America/Chicago) — never raw ISO in visible text.
- Animations are external-CSS only with a reduced-motion collapse,
  and loading skeletons stand in for live-data containers.
"""
import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent

SOCIAL = [
    "https://www.facebook.com/profile.php?id=61554735587784",
    "https://www.instagram.com/jesusthehacker/",
    "https://github.com/TheRealJesusTheHacker",
]
OLD_FOOTER_HREFS = ["/about", "/services", "/who-we-protect",
                    "/how-it-works", "/insights", "/sentinel-news",
                    "/assessment", "/tools", "/faq", "/operations",
                    "/contact", "/availability"]


def _footer(html):
    m = re.search(r"<footer.*?</footer>", html, re.S)
    if m:
        return m.group(0)
    # Static surfaces carry the footer block inside the contact section.
    i = html.index('class="foot-links"')
    return html[i - 200:html.index("</section>", i)]


def _surfaces():
    yield "templates/base.html", (SRC / "templates/base.html").read_text()
    for rel in ("site/index.html", "site/report-issue/index.html",
                "site/ticket/index.html"):
        yield rel, (SRC / rel).read_text()


def test_footer_is_slim_everywhere():
    for rel, html in _surfaces():
        foot = _footer(html)
        nav = re.search(r'<nav class="foot-links".*?</nav>', foot, re.S)
        assert nav, rel
        assert nav.group(0).count("<a ") == 2, rel
        assert 'href="/privacy"' in nav.group(0), rel
        assert 'href="/disclosure"' in nav.group(0), rel
        for href in OLD_FOOTER_HREFS:
            assert f'href="{href}"' not in foot, (rel, href)
        assert "Sentinel Safeguard LLC" in foot, rel


def test_social_links_exact_and_safe():
    for rel, html in _surfaces():
        foot = _footer(html)
        for url in SOCIAL:
            assert f'href="{url}"' in foot, (rel, url)
        assert foot.count('class="social-link"') == 3, rel
        assert 'aria-label="Sentinel Safeguard LLC on Facebook"' in foot
        assert 'aria-label="JesusTheHacker on Instagram"' in foot
        assert 'aria-label="TheRealJesusTheHacker on GitHub"' in foot
        assert foot.count('rel="noopener"') >= 3, rel
        assert "t.me" not in foot and "telegram" not in foot.lower()
        assert "freyasig" not in foot


def test_social_sprite_is_external_and_palette_safe():
    sprite = (SRC / "static/icons/social.svg").read_text()
    for sym in ("icon-facebook", "icon-instagram", "icon-github"):
        assert f'id="{sym}"' in sprite
    assert "style=" not in sprite
    css = (SRC / "static/style.css").read_text()
    assert ".social-link" in css and ".social-icon" in css


def test_no_inline_style_or_script_in_footer_surfaces():
    for rel, html in _surfaces():
        foot = _footer(html)
        assert "style=" not in foot, rel
        assert "<script" not in foot, rel


def test_ct_time_filter_registered_and_used():
    app = (SRC / "app.py").read_text()
    assert 'templates.env.filters["ct_time"]' in app
    for name in ("base.html", "index.html", "cyber_defcon.html",
                 "geopolitical_defcon.html"):
        t = (SRC / "templates" / name).read_text()
        assert "computed_at|ct_time" in t, name
        assert ">{{ cyber_defcon.computed_at }}</time>" not in t
        assert ">{{ geo_defcon.computed_at }}</time>" not in t


def test_ct_time_format():
    import importlib.util, sys, shutil, tempfile
    tmp = Path(tempfile.mkdtemp())
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    for item in ("templates", "static", "insights", "site"):
        if (SRC / item).is_dir():
            shutil.copytree(SRC / item, tmp / item)
    (tmp / "config.yaml").write_text("server:\n  port: 8443\n")
    spec = importlib.util.spec_from_file_location("feeds_ct", tmp / "feeds.py")
    fm = importlib.util.module_from_spec(spec); sys.modules["feeds_ct"] = fm
    spec.loader.exec_module(fm); sys.modules["feeds"] = fm
    spec = importlib.util.spec_from_file_location("sl_ct", tmp / "app.py")
    mod = importlib.util.module_from_spec(spec); sys.modules["sl_ct"] = mod
    spec.loader.exec_module(mod)
    # 2026-10-27T23:04:00Z is 6:04 PM in Chicago (CDT, UTC-5).
    assert mod._ct_time("2026-10-27T23:04:00+00:00") == \
        "October 27, 2026, 6:04 PM CT"
    assert mod._ct_time("") == ""
    assert mod._ct_time("not-a-date") == "not-a-date"


def test_animation_pass_is_external_and_reduced_motion_safe():
    css = (SRC / "static/style.css").read_text()
    for needle in ("@keyframes chipIn", "@keyframes heroIn",
                   "@keyframes sklSweep", ".skl", "markerIn"):
        assert needle in css, needle
    assert "prefers-reduced-motion: reduce" in css
    for name in ("threat_map.html", "internet_weather.html",
                 "geopolitical.html"):
        t = (SRC / "templates" / name).read_text()
        assert 'class="skl"' in t, name
    for js in ("threat-map.js", "internet-weather.js", "geopolitical.js"):
        t = (SRC / "static/js" / js).read_text()
        assert "fmtCT" in t and "America/Chicago" in t, js
