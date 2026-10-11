# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""``xspct-hook`` console entrypoint."""

from __future__ import annotations

import argparse
import logging

import uvicorn

from xspct_hook.app import create_app
from xspct_hook.config import load_config


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="xspct-hook")
    parser.add_argument("--config", required=True, help="path to the YAML config file")
    parser.add_argument("--log-level", default="info", help="uvicorn/root log level")
    args = parser.parse_args(argv)

    logging.basicConfig(level=args.log_level.upper())

    config = load_config(args.config)
    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
