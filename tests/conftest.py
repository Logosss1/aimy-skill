"""Shared pytest configuration.

Keeps the suite hermetic by default:
- loopback traffic bypasses any system/CI proxy;
- tests marked ``online`` are skipped unless ``--run-online`` is passed.
"""

import os

import pytest

# Some CI/dev environments configure an HTTP proxy that also captures
# 127.0.0.1. Local OOB/C2/HTTP fixtures must never go through it.
for _key in ("NO_PROXY", "no_proxy"):
    _hosts = [h.strip() for h in os.environ.get(_key, "").split(",") if h.strip()]
    for _host in ("127.0.0.1", "localhost", "::1"):
        if _host not in _hosts:
            _hosts.append(_host)
    os.environ[_key] = ",".join(_hosts)


def pytest_addoption(parser):
    parser.addoption(
        "--run-online",
        action="store_true",
        default=False,
        help="run tests marked online (real network access)",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-online"):
        return
    skip_online = pytest.mark.skip(reason="needs network; pass --run-online")
    for item in items:
        if "online" in item.keywords:
            item.add_marker(skip_online)
