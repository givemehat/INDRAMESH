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
    net = Network(height="620px", width="100%", bgcolor="#0e1117", font_color="white", directed=True)
    added = set()
    net.add_node("App", label="Scanned application", color="#00ff9f", shape="star", size=30)
    added.add("App")

    for f in findings:
        file_node = os.path.basename(str(f.get("file", "unknown")))
        risk = (f.get("risk") or {}).get("tier", "LOW")
        is_library = f.get("type") == "library"
        label = f"{f['name']}" + (f" ({f['key_length']})" if f.get("key_length") else "")
        title = (f"Tier: {risk}\n"
                 f"Primitive: {f.get('primitive', '-')}\n"
                 f"Rule: {f.get('rule_id', '-')}\n"
                 f"Evidence: {f.get('evidence_class', '-')}")
        if is_library:
            title = "LIBRARY (implements, not uses)\n" + title

        if file_node not in added:
            net.add_node(file_node, label=file_node, color="#ffffff", shape="box")
            added.add(file_node)
            net.add_edge("App", file_node)

        node_id = f"{file_node}____{f['name']}"
        if node_id in added:
            continue
        net.add_node(node_id, label=label, title=title,
                     color="#8d99ae" if is_library else COLORS.get(risk, "#4cc9f0"),
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

    return html
