#!/usr/bin/env python3
"""Create local evidence manifests with metadata and SHA-256 hashes."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from common.output import emit_json, format_table
from common.sec import file_sha256, marker, overall, stat_metadata
from common.state import ensure_state_dir, resolve_state_dir


def parse_targets(text: str) -> List[str]:
    targets = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    return targets


def expand_targets(targets: Iterable[str], max_files: int) -> List[Path]:
    paths = []
    for target in targets:
        path = Path(target)
        if path.is_file() or path.is_symlink():
            paths.append(path)
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if len(paths) >= max_files:
                    return paths
                if child.is_file() or child.is_symlink():
                    paths.append(child)
        if len(paths) >= max_files:
            break
    return paths[:max_files]


def build_manifest(targets: Iterable[str], max_files: int, max_bytes: int) -> Dict[str, Any]:
    files = []
    for path in expand_targets(targets, max_files):
        meta = stat_metadata(path)
        if meta.get("type") == "file":
            meta.update(file_sha256(path, max_bytes))
        files.append(meta)
    return {
        "tool": "evidencetrail",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "targets": list(targets),
        "files": files,
        "file_count": len(files),
    }


def manifest_path(state: Optional[str], case: str) -> Path:
    base = ensure_state_dir(state) / "evidencetrail" / case
    base.mkdir(parents=True, exist_ok=True)
    return base / "manifest.json"


def record(target_file: Optional[str], paths: Optional[str], case: str, max_files: int, max_bytes: int, state: Optional[str]) -> Dict[str, Any]:
    targets: List[str] = []
    if target_file:
        try:
            targets.extend(parse_targets(Path(target_file).read_text(encoding="utf-8", errors="replace")))
        except OSError as exc:
            targets.append(f"ERROR:{exc}")
    if paths:
        targets.extend([item.strip() for item in paths.split(",") if item.strip()])
    manifest = build_manifest([item for item in targets if not item.startswith("ERROR:")], max_files, max_bytes)
    manifest["warnings"] = [item for item in targets if item.startswith("ERROR:")]
    path = manifest_path(state, case)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    manifest["manifest_path"] = str(path)
    return manifest


def verify(case: str, state: Optional[str]) -> Dict[str, Any]:
    path = resolve_state_dir(state) / "evidencetrail" / case / "manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"tool": "evidencetrail", "case": case, "error": str(exc), "findings": [{"severity": "CRITICAL", "message": "manifest could not be read"}], "overall": "CRITICAL"}
    findings = []
    checked = []
    for item in manifest.get("files", []):
        if item.get("type") != "file" or not item.get("sha256"):
            continue
        current = file_sha256(Path(item["path"]), item.get("bytes_hashed"))
        changed = current.get("sha256") != item.get("sha256")
        checked.append({"path": item["path"], "changed": changed, "old_sha256": item.get("sha256"), "new_sha256": current.get("sha256")})
        if changed:
            findings.append({"severity": "CRITICAL", "message": f"hash changed: {item['path']}"})
    return {"tool": "evidencetrail", "case": case, "checked": checked, "findings": findings, "overall": overall(findings), "manifest_path": str(path)}


def print_manifest(report: Dict[str, Any], no_color: bool = False) -> None:
    print("evidencetrail: evidence manifest")
    if "error" in report:
        print(f"overall: {marker(report.get('overall', 'CRITICAL'), no_color)} {report.get('overall', 'CRITICAL')}")
        print(report["error"])
        return
    print(f"files: {report.get('file_count', len(report.get('checked', [])))}")
    print(f"overall: {marker(report.get('overall', 'OK'), no_color)} {report.get('overall', 'OK')}")
    rows = report.get("checked") or report.get("files", [])[:20]
    print()
    print(format_table(rows, ["path", "type", "mode", "sha256"]) if rows and "type" in rows[0] else format_table(rows, ["path", "changed"]) if rows else "  none")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Record or verify local evidence manifests under --state.")
    add_common_flags(parser)
    parser.add_argument("--state")
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record")
    add_common_flags(rec, suppress=True)
    rec.add_argument("--case", default="default")
    rec.add_argument("--targets", help="File containing one path per line.")
    rec.add_argument("--paths", help="Comma-separated files or directories.")
    rec.add_argument("--max-files", type=int, default=500)
    rec.add_argument("--max-bytes", type=int, default=25 * 1024 * 1024)
    ver = sub.add_parser("verify")
    add_common_flags(ver, suppress=True)
    ver.add_argument("--case", default="default")
    return parser


def add_common_flags(parser: argparse.ArgumentParser, suppress: bool = False) -> None:
    default = argparse.SUPPRESS if suppress else None
    parser.add_argument("--json", action="store_true", default=default)
    parser.add_argument("--no-color", action="store_true", default=default)
    if suppress:
        parser.add_argument("--state", default=argparse.SUPPRESS)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "record":
        report = record(args.targets, args.paths, args.case, args.max_files, args.max_bytes, args.state)
    else:
        report = verify(args.case, args.state)
    emit_json(report) if args.json else print_manifest(report, args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
