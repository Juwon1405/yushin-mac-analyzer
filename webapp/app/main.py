from __future__ import annotations

import argparse
import threading
import webbrowser

from .server import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="macOS DFIR Web Analyzer")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=17888, type=int)
    parser.add_argument("--open", action="store_true", help="Open browser automatically")
    parser.add_argument("--debug", action="store_true")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    app = create_app()
    url = f"http://{args.host}:{args.port}"

    if args.open:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
