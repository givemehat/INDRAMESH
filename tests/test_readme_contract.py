"""README contract tests: the claims a reader acts on must stay true.

This file exists because of what it caught on its first run. The README is the product's
front door, and three of its claims had drifted from the tree it describes:

  * the badge said 893 tests while the suite ran 945;
  * the badge said 131 rules while `engine/scanner.py` shipped 145;
  * two badges linked to `#quickstart`, a section that does not exist, and a third linked to
    a Streamlit deploy of an `app.py` that stopped being a Streamlit app commits ago.

None of that breaks a test, so it survived. These assertions make the README part of the
build: a claim that stops matching the tree fails here instead of embarrassing a demo.
"""
import re
from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"


def _text():
    return README.read_text(encoding="utf-8")


def _slug(heading):
    """GitHub's anchor slug: lowercase, spaces to hyphens, punctuation dropped."""
    slug = heading.strip().lower()
    slug = re.sub(r"[^\w\- ]", "", slug)
    return slug.replace(" ", "-")


def test_badge_links_point_at_sections_that_exist():
    """A badge that links nowhere is worse than no badge: it looks like a resource."""
    text = _text()
    anchors = re.findall(r"\]\(#([a-z0-9\-]+)\)", text)
    assert anchors, "expected at least one in-page anchor link"
    headings = {_slug(m) for m in re.findall(r"^#{1,3} (.+)$", text, flags=re.M)}
    missing = [a for a in set(anchors) if a not in headings]
    assert not missing, f"README links to sections that do not exist: {sorted(missing)}"


def test_pytest_badge_is_not_staler_than_the_suite():
    """The badge must not trail the collected test count by more than the tolerance.

    A badge is always BEHIND reality when tests are added, and always AHEAD when they are
    deleted; the tolerance absorbs environment-specific collection differences (a module
    that skips collection on a machine without an optional dependency) while still failing
    on the drift this test was written for -- 893 advertised against 953 collected.
    """
    import subprocess
    import sys

    proc = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q"],
                          capture_output=True, text=True, cwd=str(README.parent), timeout=300)
    # pytest prints either "958 tests collected" or, when the suite contains parameterized
    # nodes with ids, "957/958 tests collected (1 deselected)". Take the numerator when the
    # fraction is present so deselected `slow` tests do not inflate the comparison.
    match = re.search(r"^(?:(\d+)/)?(\d+) tests? collected", proc.stdout, flags=re.M)
    assert match, f"could not parse a collected-test count from pytest output:\n{proc.stdout[-500:]}"
    collected = int(match.group(1) or match.group(2))

    badge = re.search(r"Pytest-(\d+)_Passing", _text())
    assert badge, "the Pytest badge disappeared or changed shape"
    advertised = int(badge.group(1))

    assert advertised >= collected - 15, (
        f"the badge advertises {advertised} tests but {collected} are collected -- "
        f"update the badge (and GUIDE.md's count) in the same commit that changed the suite"
    )


def test_rule_count_badge_matches_the_rule_table():
    from engine.scanner import RULES

    badge = re.search(r"Detection-(\d+)_Rules", _text())
    assert badge, "the rules badge disappeared or changed shape"
    assert int(badge.group(1)) == len(RULES), (
        f"badge says {badge.group(1)} rules, engine.scanner.RULES has {len(RULES)}"
    )


def test_no_streamlit_deploy_link_remains():
    """`app.py` is a FastAPI launcher; a Streamlit deploy button cannot work."""
    assert "share.streamlit.io" not in _text()
