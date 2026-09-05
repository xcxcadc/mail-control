#!/usr/bin/env python3
import argparse
import getpass
import os
import shlex
import sys
import time
from pathlib import Path

import paramiko
import socks


ROOT = Path(__file__).resolve().parent


def build_parser():
    env = os.environ.get
    parser = argparse.ArgumentParser(
        description="Upload Mail Control and run the same validated installer over SSH."
    )
    parser.add_argument("--host", default=env("MAIL_CONTROL_HOST"))
    parser.add_argument("--user", default=env("MAIL_CONTROL_SSH_USER", "root"))
    parser.add_argument("--socks-host", default=env("MAIL_CONTROL_SOCKS_HOST", "127.0.0.1"))
    parser.add_argument("--socks-port", type=int, default=int(env("MAIL_CONTROL_SOCKS_PORT", "10808")))
    parser.add_argument("--timeout", type=int, default=int(env("MAIL_CONTROL_SSH_TIMEOUT", "300")))
    parser.add_argument("--mailu-dir", default=env("MAIL_CONTROL_REMOTE_MAILU_DIR", ""))
    parser.add_argument("--front-container", default=env("MAIL_CONTROL_REMOTE_FRONT_CONTAINER", ""))
    parser.add_argument("--bind", default=env("MAIL_CONTROL_REMOTE_BIND", ""))
    parser.add_argument("--port", default=env("MAIL_CONTROL_REMOTE_PORT", ""))
    return parser


def get_password(parser):
    password = os.environ.get("MAIL_CONTROL_SSH_PASSWORD", "")
    if password:
        return password
    if sys.stdin.isatty():
        return getpass.getpass("SSH password: ")
    parser.error("set MAIL_CONTROL_SSH_PASSWORD or run this command from an interactive terminal")


def connect(args, password):
    sock = socks.create_connection(
        (args.host, 22),
        proxy_type=socks.SOCKS5,
        proxy_addr=args.socks_host,
        proxy_port=args.socks_port,
        timeout=args.timeout,
    )
    transport = paramiko.Transport(sock)
    transport.banner_timeout = args.timeout
    transport.auth_timeout = args.timeout
    try:
        transport.connect(username=args.user, password=password)
    except Exception:
        transport.close()
        raise
    client = paramiko.SSHClient()
    client._transport = transport
    return client


def put_file(sftp, local_path, remote_path, mode):
    sftp.put(str(local_path), remote_path)
    sftp.chmod(remote_path, mode)


def remote_env(args):
    values = {
        "MAIL_CONTROL_MAILU_DIR": args.mailu_dir,
        "MAIL_CONTROL_FRONT_CONTAINER": args.front_container,
        "MAIL_CONTROL_BIND": args.bind,
        "MAIL_CONTROL_PORT": args.port,
    }
    return " ".join(
        f"{key}={shlex.quote(value)}"
        for key, value in values.items()
        if value
    )


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.host:
        parser.error("--host or MAIL_CONTROL_HOST is required")
    if args.socks_port <= 0 or args.socks_port > 65535:
        parser.error("--socks-port must be between 1 and 65535")
    if args.timeout < 30:
        parser.error("--timeout must be at least 30 seconds")
    password = get_password(parser)

    client = None
    sftp = None
    remote_dir = f"/tmp/mail-control-deploy-{int(time.time())}-{os.getpid()}"
    try:
        print(
            f"[mail-control] connecting to {args.host}:22 via "
            f"{args.socks_host}:{args.socks_port}",
            flush=True,
        )
        client = connect(args, password)
        sftp = client.open_sftp()
        sftp.mkdir(remote_dir, mode=0o700)
        put_file(sftp, ROOT / "install.sh", f"{remote_dir}/install.sh", 0o700)
        put_file(sftp, ROOT / "mail_control.py", f"{remote_dir}/mail_control.py", 0o750)

        env_prefix = remote_env(args)
        env_prefix = f"{env_prefix} " if env_prefix else ""
        quoted_dir = shlex.quote(remote_dir)
        command = (
            "set -Eeuo pipefail; "
            f"remote_dir={quoted_dir}; "
            "trap 'rm -rf -- \"$remote_dir\"' EXIT; "
            f"{env_prefix}bash \"$remote_dir/install.sh\" --source-dir \"$remote_dir\""
        )
        stdin, stdout, stderr = client.exec_command(
            command,
            timeout=args.timeout,
            get_pty=True,
        )
        stdin.close()
        output = stdout.read().decode("utf-8", "replace")
        error = stderr.read().decode("utf-8", "replace")
        if output:
            print(output, end="")
        if error:
            print(error, end="", file=sys.stderr)
        status = stdout.channel.recv_exit_status()
        if status:
            raise SystemExit(status)
        print("[mail-control] deployment completed", flush=True)
    except SystemExit:
        raise
    except Exception as exc:
        raise SystemExit(f"[mail-control] deployment failed: {exc}") from exc
    finally:
        if sftp is not None:
            sftp.close()
        if client is not None:
            client.close()


if __name__ == "__main__":
    main()
