#!/usr/bin/env python3
"""Migrate a Sentinel Live config from a plaintext admin key to a hash.

REMEDIATION 5a (2026-10-26). Run this ON THE SERVER, in place, against
the live config:

    python tools/hash_admin_key.py [/path/to/config.yaml]

What it does, and only this:

  * reads the config and takes the top-level ``admin_key`` (plaintext)
    value from it;
  * computes ``admin_key_sha256 = sha256(admin_key)`` (hex digest) in
    memory;
  * writes a timestamped backup of the pre-migration config next to
    the original (``config.yaml.bak-YYYYMMDD-HHMMSS``, mode 600);
  * rewrites the config surgically: the ``admin_key:`` line becomes
    ``admin_key_sha256: "<digest>"`` (or an existing empty
    ``admin_key_sha256:`` line is filled and the plaintext line is
    deleted). Every other line — every other field, comment and
    ordering — is preserved byte-for-byte.

Safety properties:

  * the plaintext key and its digest are NEVER printed, logged or
    written anywhere except the digest in the migrated config;
  * the rewrite is atomic (temp file in the same directory +
    os.replace) and the migrated file keeps the original file's
    permission bits (600 in production);
  * it REFUSES to run (exit 2, no file touched, no backup made) when
    there is nothing safe to do: no plaintext ``admin_key``, an empty
    plaintext value, a non-string value, a non-empty hash already
    present alongside plaintext (ambiguous — an operator must decide
    which value is the real key), duplicate top-level fields, or an
    unparseable config;
  * a config that is already migrated (hash present, no plaintext)
    is reported as such and left completely untouched — running the
    tool twice never creates a second backup or re-writes the file.

Rollback: restore the timestamped backup over the config and restart
the service; the pre-migration app build (and the transition support
in the new build) both read the plaintext form.

Stdlib only, except PyYAML — already a hard dependency of the app
itself (app.py imports yaml), used here only to parse the existing
value reliably. No new dependency is introduced.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - app env always has yaml
    yaml = None

_PLAIN_RE = re.compile(r"^admin_key\s*:")
_HASH_RE = re.compile(r"^admin_key_sha256\s*:")

EXIT_OK = 0
EXIT_REFUSED = 2


def _fail(message: str) -> int:
    print(f"hash_admin_key: refused: {message}", file=sys.stderr)
    return EXIT_REFUSED


def migrate(config_path: Path) -> int:
    """Migrate one config file in place. Returns a process exit code.

    Never prints the key or its digest.
    """
    if yaml is None:
        return _fail("PyYAML is not available in this Python "
                     "environment; run with the app's environment")
    if not config_path.is_file():
        return _fail(f"config file not found: {config_path}")

    raw = config_path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _fail("config file is not valid UTF-8")
    try:
        parsed = yaml.safe_load(text)
    except Exception:
        return _fail("config file could not be parsed as YAML")
    if not isinstance(parsed, dict):
        return _fail("config top level is not a mapping")

    plaintext = parsed.get("admin_key")
    existing_hash = parsed.get("admin_key_sha256")

    if plaintext is None and existing_hash:
        print("hash_admin_key: already migrated "
              "(admin_key_sha256 is set and no plaintext admin_key "
              "is present); nothing done")
        return EXIT_REFUSED
    if plaintext is None:
        return _fail("no top-level admin_key field found")
    if not isinstance(plaintext, str):
        return _fail("admin_key value is not a string "
                     f"(type {type(plaintext).__name__})")
    if plaintext == "":
        return _fail("admin_key is empty; there is no key to migrate "
                     "(set admin_key_sha256 directly for a new key)")
    if isinstance(existing_hash, str) and existing_hash != "":
        return _fail("both admin_key and a non-empty "
                     "admin_key_sha256 are present; refusing to "
                     "guess which is the real key — resolve manually")
    if existing_hash is not None and not isinstance(existing_hash, str):
        return _fail("admin_key_sha256 value is not a string "
                     f"(type {type(existing_hash).__name__})")

    lines = text.splitlines(keepends=True)
    plain_idx = [i for i, ln in enumerate(lines) if _PLAIN_RE.match(ln)]
    hash_idx = [i for i, ln in enumerate(lines) if _HASH_RE.match(ln)]
    if len(plain_idx) != 1:
        return _fail(f"expected exactly one top-level admin_key line, "
                     f"found {len(plain_idx)}")
    if len(hash_idx) > 1:
        return _fail(f"expected at most one top-level "
                     f"admin_key_sha256 line, found {len(hash_idx)}")

    digest = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    plaintext = None  # drop our reference; the value is not used again

    new_lines = list(lines)
    hash_line = f'admin_key_sha256: "{digest}"\n'
    if hash_idx:
        new_lines[hash_idx[0]] = hash_line
        del new_lines[plain_idx[0]]
    else:
        new_lines[plain_idx[0]] = hash_line
    new_text = "".join(new_lines)

    # Sanity-check the rewrite before anything is written: it must
    # parse, carry exactly the computed digest, and carry no plaintext
    # admin_key field anymore.
    try:
        check = yaml.safe_load(new_text)
    except Exception:
        return _fail("internal check failed: rewritten config "
                     "does not parse; original left untouched")
    if not isinstance(check, dict) \
            or check.get("admin_key_sha256") != digest \
            or "admin_key" in check:
        return _fail("internal check failed: rewritten config does "
                     "not verify; original left untouched")

    original_mode = stat.S_IMODE(config_path.stat().st_mode)

    # Timestamped backup of the pre-migration config, owner-only.
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = config_path.with_name(f"{config_path.name}.bak-{stamp}")
    counter = 1
    while backup.exists():
        backup = config_path.with_name(
            f"{config_path.name}.bak-{stamp}-{counter}")
        counter += 1
    shutil.copyfile(config_path, backup)
    os.chmod(backup, 0o600)

    # Atomic rewrite preserving the original permission bits.
    fd, tmp_name = tempfile.mkstemp(dir=str(config_path.parent),
                                    prefix=config_path.name + ".",
                                    suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(new_text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_name, original_mode)
        os.replace(tmp_name, config_path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise

    print(f"hash_admin_key: migrated {config_path.name}: "
          f"admin_key replaced by admin_key_sha256")
    print(f"hash_admin_key: pre-migration backup: {backup.name} "
          f"(mode 600)")
    print("hash_admin_key: restart the service for the new config "
          "to take effect")
    return EXIT_OK


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Migrate a Sentinel Live config's plaintext "
                    "admin_key to admin_key_sha256, in place.")
    parser.add_argument(
        "config", nargs="?", default="config.yaml",
        help="path to config.yaml (default: ./config.yaml)")
    args = parser.parse_args(argv)
    return migrate(Path(args.config))


if __name__ == "__main__":
    raise SystemExit(main())
