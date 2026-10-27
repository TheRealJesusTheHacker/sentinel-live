"""Site polish pins (2026-10-25) — the black/green theme is guarded,
not remembered.

The full-site polish pass (SITE-POLISH-2026-10-25) collapsed the
site's color literals from 109 unique values to the documented
system below. These pins fail if a new hex or rgb() triple appears
in the site's stylesheets, static pages, or templates without being
added to the enumerated sets HERE — drift has to be a deliberate,
reviewed act again, never an accident of a long CSS file.

Sets:
  ON_THEME — the token family (#060806 base, #00e676 and its
    documented derivations), the neutral black/white scale, and
    the near-black greens the map shimmer and radar visual use.
  DATA — functional data colors: map/data-viz encodings (threat
    volume scale, geopolitical hotspot, flight altitude bands,
    route underlay, aircraft-on-ground white). Data, not chrome —
    enumerated so the exception can never quietly widen.
  STATUS — the semantic status tints (ok/error/stale fills and
    borders) in the shared stylesheet. Functional, like DATA.
  RGB_TRIPLES — every rgb()/rgba() channel triple in use; the
    green triple is #00e676's, the red triple is the DATA red's,
    the rest are neutrals and the two light-green derivations.
"""
import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent

ON_THEME = {
    "#000", "#00a455", "#00c163", "#00e676", "#04120a", "#060806",
    "#070a08", "#0c100d", "#0d1710", "#101511", "#111711", "#141d16",
    "#1d2b20", "#223527", "#57f2a3", "#7d8a7e", "#7dffb0", "#8cffc4",
    "#d7e0d8", "#eafff3", "#fff",
}
DATA = {
    "#003d1f", "#ff4444", "#ff7b33", "#ff8888", "#ff8a3c", "#ffb300",
    "#ffd9d9", "#ffe082", "#ffe9c9", "#ffffff",
}
STATUS = {"#0a2a16", "#241a00", "#2a0d0d", "#2a2107", "#5c2222", "#5c4a14"}
RGB_TRIPLES = {
    (0, 0, 0), (0, 230, 118), (255, 255, 255), (255, 68, 68),
    (12, 16, 13), (140, 255, 196), (204, 255, 226), (6, 10, 7),
    (6, 8, 6),
}
ALLOWED_HEX = ON_THEME | DATA | STATUS

# Hex literals: 3/6/8 hex digits, not preceded by & (HTML entities
# like &#9992; — the aircraft glyph — are not colors).
HEX_RE = re.compile(r"(?<!&)#[0-9a-fA-F]{8}\b|(?<!&)#[0-9a-fA-F]{6}\b|(?<!&)#[0-9a-fA-F]{3}\b")
RGB_RE = re.compile(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)")


def _surface_files():
    files = [SRC / "static/style.css"]
    # CSP pass 2026-10-27: the static pages' stylesheets were
    # extracted into these two first-party files — they stay under
    # the palette guard. (static/fonts.css and the vendored Leaflet
    # stylesheet are generated/vendor files, not house surfaces.)
    files += [SRC / "static/site-home.css", SRC / "static/site-forms.css"]
    files += sorted((SRC / "site").rglob("*.html"))
    files += sorted((SRC / "templates").glob("*.html"))
    return files


def test_no_unlisted_colors_anywhere():
    offenders = []
    for path in _surface_files():
        text = path.read_text(encoding="utf-8")
        for match in HEX_RE.finditer(text):
            if match.group(0).lower() not in ALLOWED_HEX:
                offenders.append(f"{path.relative_to(SRC)}: {match.group(0)}")
        for match in RGB_RE.finditer(text):
            triple = tuple(int(match.group(i)) for i in (1, 2, 3))
            if triple not in RGB_TRIPLES:
                offenders.append(f"{path.relative_to(SRC)}: rgb{triple}")
    assert not offenders, "unlisted colors (add deliberately or fix):\n" + "\n".join(offenders)


def _page_with_css(path):
    """A static page plus the first-party stylesheet it links (CSP
    pass 2026-10-27 extracted the pages' <style> blocks into
    static/site-*.css; the design tokens live there now)."""
    text = path.read_text(encoding="utf-8")
    m = re.search(r'href="/static/(site-[a-z]+\.css)"', text)
    if m:
        text += (SRC / "static" / m.group(1)).read_text(encoding="utf-8")
    return text


def test_static_pages_are_dark_only_on_the_named_base():
    for path in sorted((SRC / "site").rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        assert 'content="dark"' in text, path
        assert "prefers-color-scheme: light" not in text, path
        assert "#f2f4f1" not in text, path  # the old light scheme's base
        assert "--bg:#060806" in _page_with_css(path), path


def test_app_base_token_and_theme_color_are_the_named_base():
    css = (SRC / "static/style.css").read_text(encoding="utf-8")
    assert "--bg: #060806;" in css
    assert "#060807" not in css  # one blue step off the named base
    base = (SRC / "templates/base.html").read_text(encoding="utf-8")
    assert '<meta name="theme-color" content="#060806">' in base


def test_typography_loading_is_one_system():
    # CSP pass 2026-10-27: typography is self-hosted — every surface
    # loads the same first-party fonts.css and no Google Fonts URL
    # remains anywhere in the page sources.
    base = (SRC / "templates/base.html").read_text(encoding="utf-8")
    assert 'href="/static/fonts.css"' in base
    assert "fonts.googleapis.com" not in base
    for path in sorted((SRC / "site").rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        assert 'href="/static/fonts.css"' in text, path
        assert "fonts.googleapis.com" not in text, path
    css = (SRC / "static" / "fonts.css").read_text(encoding="utf-8")
    assert "font-family: 'Archivo'" in css
    assert "font-family: 'IBM Plex Mono'" in css


def test_radius_tokens_match_across_systems():
    css = (SRC / "static/style.css").read_text(encoding="utf-8")
    for token in ("--r-s: 8px", "--r-m: 12px", "--r-l: 16px"):
        assert token in css
    for path in sorted((SRC / "site").rglob("*.html")):
        text = _page_with_css(path)
        for token in ("--radius-s:8px", "--radius-m:12px", "--radius-l:16px"):
            assert token in text, (path, token)
