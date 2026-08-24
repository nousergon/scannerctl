from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from scannerctl import __version__
from scannerctl.backend import GitleaksBackend
from scannerctl.metrics import Metrics
from scannerctl.proxy import ProxyServer, RouteTable
from scannerctl.runtime import Scanner


def _bundle_root() -> Path:
    executable = Path(sys.executable).resolve()
    if executable.name.startswith("scannerctl"):
        return executable.parent.parent
    return Path(__file__).resolve().parents[2]


def _defaults() -> tuple[Path, Path]:
    root = _bundle_root()
    gitleaks = root / "bin" / "gitleaks"
    if not gitleaks.exists():
        gitleaks = Path(os.environ.get("SCANNERCTL_GITLEAKS", "gitleaks"))
    config = root / "config" / "baseline.toml"
    if not config.exists():
        config = Path(os.environ.get("SCANNERCTL_CONFIG", config))
    return gitleaks, config


def _scanner(args) -> Scanner:
    default_binary, default_config = _defaults()
    config = Path(args.config or default_config)
    backend = GitleaksBackend(
        args.backend or default_binary,
        config,
        timeout=args.timeout,
    )
    return Scanner(
        backend,
        config,
        target_id=args.target_id,
        disabled=args.disabled,
    )


def _scan_file(args):
    payload = (
        sys.stdin.buffer.read()
        if args.input == "-"
        else Path(args.input).read_bytes()
    )
    if len(payload) > args.max_bytes:
        raise ValueError("input exceeds --max-bytes")
    return _scanner(args).scan(payload)


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config")
    parser.add_argument("--backend")
    parser.add_argument("--target-id", default=os.environ.get("SCANNERCTL_TARGET_ID", "standalone"))
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--disabled", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scannerctl")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan")
    _common(scan)
    scan.add_argument("--input", required=True)
    scan.add_argument("--format", choices=("json",), default="json")
    scan.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)

    self_test = sub.add_parser("self-test")
    _common(self_test)
    self_test.add_argument("--format", choices=("json",), default="json")

    serve = sub.add_parser("serve")
    _common(serve)
    serve.add_argument("--listen", default="127.0.0.1:8990")
    serve.add_argument("--routes", required=True)
    serve.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)

    version = sub.add_parser("version")
    version.add_argument("--format", choices=("json",), default="json")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "version":
        print(json.dumps({"schema_version": "1", "runtime_version": __version__}))
        return 0
    if args.command == "scan":
        try:
            result = _scan_file(args)
        except (OSError, ValueError):
            return 20
        print(result.to_json())
        verdict = result.verdict.value
        return 0 if verdict == "clean" else (10 if verdict == "block" else 20)
    scanner = _scanner(args)
    canary = scanner.self_test()
    if args.command == "self-test":
        print(
            json.dumps(
                {
                    "schema_version": "1",
                    "success": canary.success,
                    "benign": json.loads(canary.benign.to_json()),
                    "must_detect": json.loads(canary.must_detect.to_json()),
                },
                sort_keys=True,
            )
        )
        return 0 if canary.success else 20
    if not canary.success:
        return 20
    host, separator, port = args.listen.rpartition(":")
    if not separator or not port.isdigit():
        raise ValueError("--listen must be HOST:PORT")
    metrics = Metrics(
        runtime_version=__version__,
        config_sha256=scanner.config_sha256,
    )
    metrics.set_canary(success=True)
    server = ProxyServer(
        (host, int(port)),
        scanner=scanner,
        routes=RouteTable.from_json(args.routes),
        metrics=metrics,
        max_body_bytes=args.max_bytes,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
