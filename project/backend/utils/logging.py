from __future__ import annotations

import logging
import sys


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stdout,
        force=True,
    )
    for noisy in ("httpx", "httpcore", "pymongo", "neo4j", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
