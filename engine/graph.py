"""Interactive topology graph (PyVis).

Nodes: the scanned application, each file, and each cryptographic artefact.
Edges: file -> artefact (`uses`). A library finding is presence evidence, so it is rendered
differently from a primitive that code actually calls.
"""
import functools
import os
import re
import tempfile

from pyvis.network import Network

COLORS = {"CRITICAL": "#ff4b4b", "HIGH": "#ff9f36", "MEDIUM": "#ffd166", "LOW": "#4cc9f0"}
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@functools.lru_cache(maxsize=1)
def _vendor_assets():
    """Load local vendor JS/CSS so the graph functions fully offline without relative 404s."""
    vis_js, vis_css, utils_js = "", "", ""
    vis_js_path = os.path.join(REPO_ROOT, "lib", "vis-9.1.2", "vis-network.min.js")
    vis_css_path = os.path.join(REPO_ROOT, "lib", "vis-9.1.2", "vis-network.css")
    utils_js_path = os.path.join(REPO_ROOT, "lib", "bindings", "utils.js")

    if os.path.exists(vis_js_path):
        with open(vis_js_path, "r", encoding="utf-8") as f:
            vis_js = f.read()
    if os.path.exists(vis_css_path):
        with open(vis_css_path, "r", encoding="utf-8") as f:
            vis_css = f.read()
    if os.path.exists(utils_js_path):
        with open(utils_js_path, "r", encoding="utf-8") as f:
            utils_js = f.read()

    return vis_js, vis_css, utils_js


def generate_crypto_graph(findings):
    # Enterprise-grade: tolerate None / non-list callers (e.g. empty scan
    # bundle) -- render the App-only skeleton instead of raising TypeError.
    if not isinstance(findings, (list, tuple)):
        findings = []
    net = Network(height="620px", width="100%", bgcolor="#0e1117", font_color="white", directed=True)
    added = set()
    net.add_node("App", label="Scanned application", color="#00ff9f", shape="star", size=30)
    added.add("App")

    for f in findings:
        if not isinstance(f, dict):
            continue
        raw_file = str(f.get("file") or "unknown").replace("\\", "/").strip() or "unknown"
        # Canonicalize: collapse ./, //, trailing / while keeping full-path
        # semantics (d1/u.py vs d2/u.py must stay separate).
        import posixpath as _posixpath
        raw_file = _posixpath.normpath(raw_file)
        # Node id keeps the normalized relative path (avoids d1/u.py vs d2/u.py
        # collapse from basename), label stays human-readable basename.
        file_node = raw_file
        file_label = _posixpath.basename(raw_file) or raw_file
        _risk = f.get("risk")
        if isinstance(_risk, dict):
            risk = str(_risk.get("tier", "LOW") or "LOW").strip().upper() or "LOW"
        elif isinstance(_risk, str) and _risk.strip().upper() in COLORS:
            risk = _risk.strip().upper()
        else:
            risk = "LOW"
        name = str(f.get("name") or "unknown")
        norm_name = name.strip().casefold()
        # Distinguish variants that must not merge (RSA-2048 vs RSA-4096,
        # different curves/modes/primitives) while deduping exact repeats
        # case- and whitespace-insensitively.
        variant = "|".join([
            norm_name,
            str(f.get("primitive") or "").strip().casefold(),
            str(f.get("type") or "").strip().casefold(),
            str(f.get("key_length") or "").strip(),
            str(f.get("curve") or "").strip().casefold(),
            str(f.get("mode") or "").strip().casefold(),
        ])
        is_library = str(f.get("type") or "").strip().casefold() == "library"
        label = f"{name}" + (f" ({f['key_length']})" if f.get("key_length") else "")
        title = (f"Tier: {risk}\n"
                 f"Primitive: {f.get('primitive', '-')}\n"
                 f"Rule: {f.get('rule_id', '-')}\n"
                 f"Evidence: {f.get('evidence_class', '-')}")
        if is_library:
            title = "LIBRARY (implements, not uses)\n" + title

        if file_node not in added:
            net.add_node(file_node, label=file_label, color="#ffffff", shape="box")
            added.add(file_node)
            net.add_edge("App", file_node)

        node_id = f"{file_node}____{variant}"
        if node_id in added:
            continue
        net.add_node(node_id, label=label, title=title,
                     color="#8d99ae" if is_library else COLORS.get(str(risk).strip().upper(), "#4cc9f0"),
                     shape="dot" if is_library else "diamond", size=22)
        added.add(node_id)
        net.add_edge(file_node, node_id, dashes=is_library)

    net.force_atlas_2based()

    fd, tmp_path = tempfile.mkstemp(suffix=".html")
    os.close(fd)
    try:
        net.save_graph(tmp_path)
        with open(tmp_path, "r", encoding="utf-8") as fh:
            html = fh.read()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    # Inline local vendor assets to guarantee air-gapped offline operation without CDN or 404s
    vis_js, vis_css, utils_js = _vendor_assets()
    if utils_js:
        html = re.sub(
            r'<script\s+src="[^"]*utils\.js"></script>',
            lambda _: f"<script>\n{utils_js}\n</script>",
            html
        )
    if vis_css:
        html = re.sub(
            r'<link\s+rel="stylesheet"\s+href="[^"]*vis-network[^"]*\.css"[^>]*>',
            lambda _: f"<style>\n{vis_css}\n</style>",
            html
        )
    if vis_js:
        html = re.sub(
            r'<script\s+src="[^"]*vis-network[^"]*\.js"[^>]*></script>',
            lambda _: f"<script>\n{vis_js}\n</script>",
            html
        )
    # Enterprise-grade air-gap: pyvis template pulls Bootstrap from jsdelivr.
    # The graph works without it; strip remote refs so topology view never
    # phones home on open in an isolated enclave.
    # Both double- and single-quoted attrs, plus protocol-relative //CDN refs.
    html = re.sub(
        r"""<link[^>]*href=["'](?:https?:)?//[^"']*bootstrap[^"']*["'][^>]*>""",
        "<!-- bootstrap css removed for air-gap -->",
        html, flags=re.IGNORECASE,
    )
    html = re.sub(
        r"""<script[^>]*src=["'](?:https?:)?//[^"']*bootstrap[^"']*["'][^>]*>\s*</script>""",
        "<!-- bootstrap js removed for air-gap -->",
        html, flags=re.IGNORECASE,
    )
    # Belt-and-braces: drop any other remote src/href that slipped through
    # (match both double- and single-quoted attributes, incl. //host form).
    html = re.sub(
        r"""\s(?:src|href)=["'](?:https?:)?//(?!www\.w3\.org)[^"']*["']""",
        ' data-removed-remote="1"',
        html,
    )

    return html
