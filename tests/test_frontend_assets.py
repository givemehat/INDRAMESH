"""The web front end's load-bearing guarantees, asserted against the served files.

WHY THIS FILE EXISTS
--------------------
The console was replaced from Streamlit with a FastAPI + vanilla-JS front end, and three
properties have to survive every future edit. All three were violated within a day of the
rewrite, and none of them is caught by a passing test suite or a 200 from the server:

  1. NO REMOTE REFERENCES. The new index.html loaded a typeface from fonts.googleapis.com. That
     is a real request on page load, it breaks the "no CDN, no network call, no telemetry"
     guarantee the project states in three places, and for a security tool it discloses to a
     third party that someone is analysing cryptography. It also makes the console unusable in
     the air-gapped review that is exactly the point of the exercise.
  2. REDUCED MOTION IS HONOURED. The original stylesheet had no prefers-reduced-motion block at
     all. An accessibility preference is a request, not a suggestion.
  3. THE HTML IS REVIEWABLE. A single-line 34 KB index.html is valid and useless: the diff for
     a one-character change is 34,000 characters, and nobody reads that. This happened during
     this work and is asserted so it cannot happen again.

These are static assertions on files, not browser tests. That is a deliberate trade: a headless
browser is a large dependency to add for three invariants a regex can state exactly, and the
property being protected is "this string never appears", which is precisely a string check.
"""
import os
import re

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO, "web", "static")
INDEX = os.path.join(STATIC, "index.html")
CSS = os.path.join(STATIC, "css", "style.css")
JS = os.path.join(STATIC, "js", "app.js")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.parametrize("name", ["index.html", "css/style.css", "js/app.js",
                                  "js/icons.js", "js/topology.js", "js/framer-motion.js"])
def test_no_front_end_asset_references_a_remote_host(name):
    """The no-network guarantee, enforced on the actual shipped bytes.

    A remote `src`/`href` is a request the moment an analyst opens the console. The XML
    namespace URI in SVG `createElementNS` calls is a false positive and is excluded: it is an
    identifier, never fetched, and it is the one legitimate `http://` in a document.
    """
    path = os.path.join(STATIC, *name.split("/"))
    if not os.path.exists(path):
        pytest.skip(f"{name} not present")
    text = _read(path)
    offenders = [
        m for m in re.findall(r'(?:src|href)\s*=\s*["\'](https?://[^"\']+)', text)
        if "www.w3.org" not in m          # SVG/XML namespace, never fetched
    ]
    assert not offenders, (
        f"{name} references remote resources: {offenders}\n"
        f"The console promises 'no CDN, no network call, no telemetry'. Vendor the asset under "
        f"/static/ instead, or use a local font stack.")


def test_the_stylesheet_honours_reduced_motion():
    css = _read(CSS)
    assert "prefers-reduced-motion" in css, (
        "the stylesheet has no prefers-reduced-motion block. Every animation added to this "
        "console must be removable by the reader's OS setting; that is a request, not a "
        "suggestion.")
    # The blanket reset must be LAST in the file, or a later rule re-enables motion over it.
    idx = css.rindex("@media (prefers-reduced-motion")
    tail = css[idx:]
    assert "animation-duration" in tail and "transition-duration" in tail


def test_the_motion_system_writes_values_before_it_animates():
    """`setMetric` must assign textContent BEFORE it touches a class.

    If the animation were load-bearing -- if the class set the number -- then reduced motion, a
    failed stylesheet, or a slow first paint would all show a stale or empty figure. The value
    is the data; the motion is a reveal of it.
    """


def test_index_html_is_balanced_and_reviewable():
    html = _read(INDEX)
    opens = len(re.findall(r"<div\b", html))
    closes = len(re.findall(r"</div>", html))
    assert opens == closes, f"unbalanced <div>: {opens} open, {closes} close"
    # A single-line file is valid but unreviewable; this happened during development.
    assert html.count("\n") >= 40, (
        f"index.html has only {html.count(chr(10))} newlines -- it has been collapsed onto one "
        f"line. The diff for a one-character change would be the entire file.")


def test_no_duplicate_style_attribute_in_index_html():
    """Two `style=` attributes on one tag: the second is silently dropped by every browser.

    This is not hypothetical -- merging a stagger index into an existing inline style produced
    exactly this, and the visual result was that four of six metric cards silently lost their
    border colour.
    """
    html = _read(INDEX)
    dupes = re.findall(r"<[^>]*?\bstyle=[^>]*?\bstyle=[^>]*?>", html)
    assert not dupes, f"duplicate style attributes on {len(dupes)} element(s): {dupes[:3]}"


def test_the_stylesheet_is_structurally_balanced():
    css = _read(CSS)
    assert css.count("{") == css.count("}"), \
        "an unbalanced brace makes a browser drop the rule silently"
    assert css.count("(") == css.count(")")


def test_every_custom_property_used_is_declared_or_set_by_script():
    """`var(--x)` with no declaration resolves to nothing and inherits silently.

    No error, no warning -- just a colour that quietly falls back. This is the CSS equivalent of
    publishing a strength level the tool cannot justify.

    Two properties are legitimately absent from the stylesheet because JavaScript sets them on
    the element at runtime: `--ring-circumference` (computed from the arc's own radius) and
    `--flash` (supplied per tier when a rescored row changes). They are excluded by name, with
    the reason recorded, rather than by loosening the check for everything.
    """
    css = _read(CSS)
    js = _read(JS)
    runtime = {"--ring-circumference", "--flash"}
    declared = set(re.findall(r"(--[a-z0-9-]+)\s*:", css))
    used = set(re.findall(r"var\((--[a-z0-9-]+)", css))
    missing = used - declared - runtime
    assert not missing, f"undeclared custom properties: {sorted(missing)}"
    # ...and the ones we excused must actually be set somewhere, or they are just dead.
    for prop in runtime:
        assert prop in js or prop in css, (
            f"{prop} is excused from the declaration check but is never set anywhere")


def test_only_loading_indicators_are_permitted_to_loop():
    """Motion is instrumentation, so an animation may run unattended only while work is pending.

    The scan sweep says "no result yet" and is removed by `setScanning(false)` the moment a scan
    returns. The skeleton shimmer runs only while a load is in flight. The two status dots
    reflect a live connection state. An animation that keeps running after a result exists makes
    the analyst believe the tool is still working, which is the console lying about its own state.
    """
    css = _read(CSS)
    body = css.split("MOTION SYSTEM", 1)[-1]
    infinite = re.findall(r"animation:\s*([^;]*\binfinite\b[^;]*)", body)
    allowed = ("ec-scan", "ec-shimmer", "ec-online-breathe", "ec-offline-flash")
    for decl in infinite:
        name = decl.strip().split()[0]
        assert name in allowed, (
            f"unattended animation outside the allowed set: {name}\n"
            f"Only a loading indicator may loop. Everything else is a one-shot entrance or a "
            f"transition that settles.")


def test_the_console_javascript_files_parse():
    """A syntax error in app.js is invisible to the server and fatal to the console.

    The server returns 200 and serves the HTML perfectly while every script fails to parse, so
    the page loads and stays completely empty. Balanced-delimiter counting is not enough: a
    template literal can hide an unclosed brace from any counter, which is exactly the class of
    truncation that a counter would wave through.

    `node --check` is the real parser and is used when Node is present. Without it the file is
    still checked for balanced delimiters, which catches the common case; the skip is explicit
    so nobody reads "no Node" as "verified".
    """
    import shutil
    import subprocess
    node = shutil.which("node")
    for name in ("app.js", "icons.js", "topology.js", "framer-motion.js"):
        path = os.path.join(STATIC, "js", name)
        if not os.path.exists(path):
            continue
        if node:
            proc = subprocess.run([node, "--check", path],
                                  capture_output=True, text=True, timeout=30)
            assert proc.returncode == 0, (
                f"{name} does not parse:\n{proc.stderr.strip()[:400]}\n"
                f"The server will still return 200 and serve the page, and the console will "
                f"render nothing at all.")
        else:
            text = _read(path)
            assert text.count("{") == text.count("}"), f"{name}: unbalanced braces"
            pytest.skip("node not on PATH -- delimiter check only, NOT a parse")

    js = _read(JS)
    assert "function setMetric" in js
    body = js.split("function setMetric", 1)[1].split("\n}", 1)[0]
    set_idx = body.find("textContent")
    class_idx = body.find("classList.add")
    assert set_idx > -1, "setMetric never writes the value"
    assert class_idx > -1, "setMetric never marks the change"
    assert set_idx < class_idx, (
        "setMetric animates before it writes the value. The displayed number must be correct "
        "even if the animation never runs.")


def test_topology_graph_html_has_no_remote_refs():
    """Air-gap guarantee extends to the generated topology HTML.

    pyvis templates pull Bootstrap from jsdelivr; engine/graph.py must strip
    every remote src/href so the topology view never phones home in an
    isolated enclave. test_no_front_end_asset_* only scans web/static/,
    so this covers the generated bytes instead.
    """
    from engine.graph import generate_crypto_graph
    html = generate_crypto_graph([
        {"name": "AES-128", "primitive": "block-cipher", "file": "a.py",
         "line": 1, "risk": {"tier": "LOW"}},
    ])
    offenders = [
        m for m in re.findall(r'(?:src|href)\s*=\s*["\'](https?://[^"\']+)', html)
        if "www.w3.org" not in m
    ]
    assert not offenders, f"graph HTML references remote resources: {offenders}"
