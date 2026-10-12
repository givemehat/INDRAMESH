"""IndraMesh Web Console Launcher.

Replaces the legacy Streamlit front end with a modern, high-performance,
cybersecurity HUD console powered by FastAPI, Uvicorn, and HTML5/Canvas.

Usage:
    python app.py                 # Runs the console on http://127.0.0.1:8501
    python app.py --port 8000     # Runs on custom port
"""
import argparse
import os
import sys

# Ensure repository root is on sys.path
_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Importing the ASGI app is what makes `uvicorn.run("server:app")` resolve. The name is
# deliberately unused here; do not let a lint autofix delete it.
from server import app as fastapi_app  # noqa: F401

# Graceful bridge if invoked via `streamlit run app.py`
try:
    import streamlit as st
    if hasattr(st, "runtime") and st.runtime.exists():
        st.set_page_config(page_title="IndraMesh Console", layout="wide", page_icon="🛡️")
        st.title("🛡️ INDRAMESH (इन्द्रमेश)")
        st.subheader("Enterprise Cryptographic Discovery, Inventory (ACDI) & Post-Quantum Migration Mesh")
        st.info("🚀 **IndraMesh has migrated to a High-Performance FastAPI Cyber HUD Console.**")
        st.markdown(
            """
            To launch the full interactive Cyber HUD console, CycloneDX v1.7 CBOM generator,
            and real-time telemetry array, run:
            
            ```bash
            python app.py
            ```
            Then access the HUD at **http://127.0.0.1:8501**
            """
        )
except Exception:
    pass



def run_server(host: str = "127.0.0.1", port: int = 8501, reload: bool = False,
               allow_unauthenticated_public: bool = False):
    """Start the Uvicorn web server.

    The default is loopback, not 0.0.0.0. This console has no authentication and its /api/scan
    endpoint will read any path the process can read, so binding every interface by default
    turned a local analysis tool into a LAN-reachable file-inspection service the moment
    someone ran `python app.py` on a shared network.

    Binding off-loopback therefore has to be an explicit, second decision: `--host 0.0.0.0
    --allow-unauthenticated-public`. docs/COMPARISON.md records that the sibling project
    refuses to start in this configuration without a token, and lists our missing equivalent
    as a gap; this is the deliberate-response half of that gap (a token for the vanilla-JS
    console is not, because the console would have to carry the secret in the page).
    """
    import uvicorn

    off_loopback = host not in ("127.0.0.1", "localhost", "::1")
    if off_loopback and not allow_unauthenticated_public:
        raise SystemExit(
            f"refusing to bind {host}: the IndraMesh console has NO authentication and /api/scan "
            f"will read any path this process can read.\n"
            f"  * loopback only:            python app.py\n"
            f"  * accept the exposure:      python app.py --host {host} "
            f"--allow-unauthenticated-public\n"
            f"  * or put it behind a proxy / VPN that authenticates first."
        )

    print("=" * 78)
    print("IndraMesh -- Enterprise Cryptographic Discovery & Analysis Tool")
    print(f"  Console:       http://127.0.0.1:{port}")
    print(f"  API Docs:      http://127.0.0.1:{port}/docs")
    if off_loopback:
        print(f"  Bound to       {host} -- NO authentication; anyone who can reach this port can "
              f"read any path the process can read.")
    print("  Engine:        FastAPI + IndraMesh Core (Zero Streamlit requirement)")
    print("=" * 78)

    uvicorn.run("server:app", host=host, port=port, log_level="info", reload=reload)


def main():
    parser = argparse.ArgumentParser(description="Launch the IndraMesh Web Console")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Host address (default: 127.0.0.1 -- loopback only)")
    parser.add_argument("--allow-unauthenticated-public", action="store_true",
                        help="Required, together with a non-loopback --host, to expose the "
                             "unauthenticated console to the network")
    parser.add_argument("--port", type=int, default=8501, help="Port number (default: 8501)")
    parser.add_argument("--reload", action="store_true", help="Enable live auto-reload for development")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port, reload=args.reload,
               allow_unauthenticated_public=args.allow_unauthenticated_public)


if __name__ == "__main__":
    main()
