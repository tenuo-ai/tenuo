"""The local file layout and strict configuration."""

from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path

from .files import (
    DocumentError,
    fields,
    fingerprint,
    keygen,
    load_public_key,
    load_signing_key,
    load_yaml,
    name,
    publish,
    read_revocation_list,
    update_revocations,
    write_yaml,
)

DEFAULT_CONFIG = {
    "version": 1,
    "mode": "enforce",
    "issuer": "issuer",
    "dev_roots": [],
    "approvals": {"ttl": "5m"},
    "reload": {"interval": "2s"},
    "audit": {"receipts": "receipts.jsonl"},
}


class Workspace:
    def __init__(self, path=None):
        # Outside the project by default, so a warrant that scopes agent file
        # tools to the project (e.g. Subpath) also keeps them away from these keys.
        self.path = Path(path or os.environ.get("TENUO_HOME", "~/.tenuo")).expanduser().absolute()

    @property
    def config(self):
        data = load_yaml(self.path / "config.yaml")
        fields(data, DEFAULT_CONFIG, DEFAULT_CONFIG, "config")
        if type(data["version"]) is not int or data["version"] != 1:
            raise DocumentError("config: version must be 1")
        if data["mode"] not in ("enforce", "observe"):
            raise DocumentError("config: mode must be enforce or observe")
        name(data["issuer"])
        if not isinstance(data["dev_roots"], list):
            raise DocumentError("config: dev_roots must be a list of names")
        for root in data["dev_roots"]:
            name(root)
        for section, member in (("approvals", "ttl"), ("reload", "interval"), ("audit", "receipts")):
            fields(data[section], [member], [member], f"config.{section}")
            if not isinstance(data[section][member], str) or not data[section][member]:
                raise DocumentError(f"config.{section}.{member}: expected a nonempty string")
        return data

    def initialize(self, *, dev=False):
        # Refusing existing directories also prevents accidentally rotating identities.
        self.path.mkdir(mode=0o700, parents=True, exist_ok=False)
        # Protect partially initialized workspaces before generating any secret.
        publish(self.path / ".gitignore", b"*\n!.gitignore\n")
        for directory in ("keys", "trust", "warrants", "sessions", "requests", "approvals"):
            (self.path / directory).mkdir(mode=0o700)
        config = deepcopy(DEFAULT_CONFIG)
        config["dev_roots"] = ["issuer"] if dev else []
        if dev:
            for identity in ("issuer", "agent", "approver"):
                keygen(self.path / "keys" / identity)
            publish(self.path / "trust/issuer.pub", (self.path / "keys/issuer.pub").read_bytes())
            update_revocations(self.path / "revocations.srl", self.signing_key("issuer"), create=True)
        write_yaml(self.path / "config.yaml", config)
        return config

    def set_mode(self, mode):
        from .files import operator_lock

        if mode not in ("enforce", "observe"):
            raise DocumentError("mode must be enforce or observe")
        with operator_lock(self.path):
            config = self.config
            config["mode"] = mode
            write_yaml(self.path / "config.yaml", config, replace=True)
        return config

    def key_path(self, value, *, private=False):
        suffix = ".key" if private else ".pub"
        if isinstance(value, str) and "/" not in value and "\\" not in value and not value.endswith(suffix):
            return self.path / "keys" / (name(value) + suffix)
        return Path(value).expanduser()

    def signing_key(self, value):
        return load_signing_key(self.key_path(value, private=True))

    def public_key(self, value):
        return load_public_key(self.key_path(value))

    def trusted_roots(self):
        paths = sorted((self.path / "trust").glob("*.pub"))
        if not paths:
            raise DocumentError(f"{self.path}/trust: no trusted issuers; run tenuo-cli trust add --file ISSUER.pub")
        return [load_public_key(path) for path in paths]

    def authorizer(self):
        from tenuo import Authorizer

        self.config
        authorizer = Authorizer(trusted_roots=self.trusted_roots())
        authorizer.set_clock_tolerance(0)
        authorizer.set_revocation_list(read_revocation_list(self.path / "revocations.srl"))
        return authorizer

    def diagnostics(self):
        config = self.config
        checks = []
        try:
            authorizer = self.authorizer()
            checks.append({"status": "ok", "message": "Trust and signed revocation list verified"})
            del authorizer
        except Exception:
            checks.append(
                {
                    "status": "error",
                    "message": "Trust or revocation list invalid; check trust/*.pub and revocations.srl",
                }
            )
        if config["mode"] == "observe":
            checks.append(
                {
                    "status": "warning",
                    "message": "mode: observe blocks nothing; run tenuo-cli mode enforce once a warrant is attached",
                }
            )
        if config["dev_roots"]:
            checks.append(
                {
                    "status": "warning",
                    "message": "Local development identities: keep issuer and approver keys out of the agent's reach",
                }
            )
        for identity in (config["issuer"], "approver"):
            path = self.key_path(identity, private=True)
            if os.access(path, os.R_OK):
                checks.append(
                    {
                        "status": "warning",
                        "message": f"This user can read {identity}.key; separate files under one user are not process isolation",
                    }
                )
        for path in sorted((self.path / "keys").glob("*.key")):
            if path.stat().st_mode & 0o077:
                checks.append({"status": "error", "message": f"Private key permissions too broad: chmod 600 {path}"})
            public = path.with_suffix(".pub")
            if public.exists():
                try:
                    if bytes(load_signing_key(path).public_key.to_bytes()) != bytes(load_public_key(public).to_bytes()):
                        raise ValueError
                except Exception:
                    checks.append({"status": "error", "message": f"Key pair {path.stem} is invalid or mismatched; restore its matching public key or create a new identity"})
        return checks

    def key_inventory(self):
        return [
            {"name": p.stem, "fingerprint": fingerprint(load_public_key(p))}
            for p in sorted((self.path / "keys").glob("*.pub"))
        ]
