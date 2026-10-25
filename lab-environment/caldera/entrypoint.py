#!/usr/bin/env python3
"""Generate a lab-local Caldera config and start the server.

Caldera's `--insecure` mode uses the upstream default credentials, and the
auto-generated `local.yml` is a full copy of `default.yml` with random secrets.
This entrypoint does the same deterministically for the isolated lab: it reads
the image's `default.yml`, enables the `ot-lab` plugin, removes plugins we do
not ship (atomic/emu), sets lab-only credentials from the environment and
writes `conf/otlab.yml`. The server then starts with `-E otlab`.
"""
from __future__ import annotations

import os

import yaml

DEFAULT_CONFIG = "conf/default.yml"
LAB_CONFIG = "conf/otlab.yml"
REMOVED_PLUGINS = {"atomic", "emu"}


def main() -> None:
    with open(DEFAULT_CONFIG, encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    plugins = [plugin for plugin in config.get("plugins", []) if plugin not in REMOVED_PLUGINS]
    if "ot-lab" not in plugins:
        plugins.append("ot-lab")
    config["plugins"] = plugins

    password = os.getenv("CALDERA_RED_PASSWORD", "ot-lab-caldera")
    api_key = os.getenv("CALDERA_API_KEY", "ot-lab-caldera-api")
    config["users"] = {
        "red": {"red": password, "admin": password},
        "blue": {"blue": password},
    }
    config["api_key_red"] = api_key
    config["api_key_blue"] = api_key
    config["crypt_salt"] = os.getenv("CALDERA_CRYPT_SALT", "ot-lab-caldera-salt")
    config["encryption_key"] = os.getenv("CALDERA_ENCRYPTION_KEY", "ot-lab-caldera-key")
    config["app.contact.http"] = "http://0.0.0.0:8888"

    with open(LAB_CONFIG, "w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, default_flow_style=False)

    os.execvp("python3", ["python3", "server.py", "-E", "otlab"])


if __name__ == "__main__":
    main()
