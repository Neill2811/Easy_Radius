"""Run the Easy Radius web server."""

from __future__ import annotations

import os

from easy_radius.web import create_app


def main() -> None:
    app = create_app()
    host = os.environ.get("RADIUS_ADMIN_HOST", "0.0.0.0")
    port = int(os.environ.get("RADIUS_ADMIN_PORT", "8088"))
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
