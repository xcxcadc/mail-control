#!/usr/bin/env python3
"""Prepare a narrowly scoped, persistent Mailu 2024.06 password-policy override.

The tool never contacts a server or restarts a container.  Extract the production
mailu/utils.py, patch a host override copy, then mount that copy read-only in admin.
Unknown upstream validator implementations fail closed instead of being replaced.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile


UPSTREAM_VALIDATOR = '''def isBadOrPwned(form):
    try:
        if len(form.pw.data) < 8:
            return "This password is too short."
        breaches = int(form.pwned.data)
    except ValueError:
        breaches = -1
    if breaches > 0:
        return f"This password appears in {breaches} data breaches! It is not unique; please change it."
    return None
'''

CUSTOM_VALIDATOR = '''def isBadOrPwned(form):
    """Mail Control policy v1: accept any non-empty password."""
    if not form.pw.data:
        return "Password cannot be empty."
    return None
'''


def _function(source):
    tree = ast.parse(source)
    matches = [node for node in tree.body
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name == "isBadOrPwned"]
    if len(matches) != 1:
        raise ValueError("Expected exactly one top-level isBadOrPwned validator")
    return matches[0]


def _shape(node):
    return ast.dump(node, include_attributes=False)


def patch_source(source):
    """Return (patched_source, changed), preserving all unrelated source text."""
    function = _function(source)
    if _shape(function) == _shape(_function(CUSTOM_VALIDATOR)):
        return source, False
    if _shape(function) != _shape(_function(UPSTREAM_VALIDATOR)):
        raise ValueError("Unrecognized Mailu password validator; review the production source before patching")
    newline = "\r\n" if "\r\n" in source else "\n"
    lines = source.splitlines(keepends=True)
    replacement = CUSTOM_VALIDATOR.rstrip("\n").replace("\n", newline)
    original = "".join(lines[function.lineno - 1:function.end_lineno])
    if original.endswith(("\n", "\r")):
        replacement += newline
    lines[function.lineno - 1:function.end_lineno] = [replacement]
    result = "".join(lines)
    compile(result, "mailu/utils.py", "exec")
    return result, True


def _digest(content):
    return hashlib.sha256(content).hexdigest()


def _atomic_write(path, content, mode):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing to replace a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".password-policy-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def configure(source_path, output_path=None, backup_dir=None, check=False):
    source_path = Path(source_path)
    if source_path.is_symlink() or not source_path.is_file():
        raise ValueError("Source must be a regular, non-symlink Mailu utils.py file")
    original = source_path.read_bytes()
    prepared, changed = patch_source(original.decode("utf-8"))
    result = prepared.encode("utf-8")
    report = {"policy": "non-empty-password-v1", "source": str(source_path.resolve()),
              "source_sha256": _digest(original), "prepared_sha256": _digest(result),
              "validator_changed": changed, "written": False}
    if check:
        report["active_in_source"] = not changed
        return report
    if output_path is None:
        raise ValueError("An explicit output file or --in-place is required")
    output_path = Path(output_path)
    if output_path.is_symlink():
        raise ValueError("Output must not be a symlink")
    if output_path.is_file() and output_path.read_bytes() == result:
        report["output"] = str(output_path.resolve())
        return report
    if backup_dir is not None:
        # A content-addressed backup never overwrites the original after reruns.
        backup = Path(backup_dir) / ("utils." + _digest(original) + ".py")
        if backup.exists() and backup.read_bytes() != original:
            raise ValueError("Existing source backup does not match its digest")
        if not backup.exists():
            _atomic_write(backup, original, 0o600)
        report["backup"] = str(backup.resolve())
    elif output_path.resolve() == source_path.resolve():
        raise ValueError("In-place patching requires --backup-dir")
    mode = stat.S_IMODE(source_path.stat().st_mode)
    _atomic_write(output_path, result, mode)
    report.update(output=str(output_path.resolve()), written=True)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="Production mailu/utils.py extracted from the admin container")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--output", type=Path, help="Write an override copy to this explicit host path")
    target.add_argument("--in-place", action="store_true", help="Patch the source file; requires --backup-dir")
    parser.add_argument("--backup-dir", type=Path, help="Store a content-addressed backup of the source")
    parser.add_argument("--check", action="store_true", help="Report whether this source has the policy; never write")
    args = parser.parse_args(argv)
    if not args.check and not (args.output or args.in_place):
        parser.error("Choose --output, --in-place, or --check")
    try:
        report = configure(args.source, args.source if args.in_place else args.output, args.backup_dir, args.check)
    except (ValueError, OSError, SyntaxError, UnicodeError) as exc:
        parser.exit(2, "password policy: " + str(exc) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
