from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from .analyzer import AnalysisResult, ClassSummary, RetainerChainNode, RetainerSummary, analyze_snapshot
from .parser import HprofParser


_CACHE_SCHEMA_VERSION = 1
_CACHE_HASH_INDEX = "file_hash_index.json"


def main() -> int:
    try:
        args = _build_parser().parse_args()
        progress = _ProgressPrinter() if args.verbose else None

        cache_file: Path | None = None
        cached_result = None
        heap_path = Path(args.hprof_file)
        if args.cache and heap_path.exists():
            cache_dir = Path(args.cache_dir)
            cache_dir.mkdir(parents=True, exist_ok=True)
            file_hash = _get_file_hash_with_index(heap_path, cache_dir, progress=progress)
            cache_file = _cache_file_path(cache_dir, file_hash, args)
            cached_result = _load_cached_result(cache_file)
            if cached_result is not None and progress is not None:
                progress(f"Cache: hit ({cache_file})")

        if cached_result is not None:
            result = cached_result
        else:
            if progress is not None:
                progress(f"Opening heap dump: {args.hprof_file}")
            parser = HprofParser(
                include_unreachable_roots=args.include_unreachable_roots,
                progress=progress,
                workers=args.workers,
            )
            snapshot = parser.parse(heap_path)
            result = analyze_snapshot(
                snapshot,
                top_n=args.top,
                include_dominator=not args.no_dominator,
                engine=args.engine,
                work_dir=args.work_dir,
                workers=args.workers,
                max_memory_gb=args.max_memory_gb,
                progress=progress,
            )
            if args.cache and cache_file is not None:
                _save_cached_result(cache_file, result, progress=progress)

        if progress is not None:
            progress("Rendering final report")

        if args.format == "json":
            _print_json(result, args.hprof_file)
        else:
            _print_text(result, Path(args.hprof_file))
        return 0
    except KeyboardInterrupt:
        print("Interrupted by user (Ctrl+C).", file=sys.stderr, flush=True)
        return 130


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hprof-report",
        description=(
            "Read a JVM HPROF heap dump and report memory retained by objects "
            "reachable from GC roots (non-collectable at snapshot time)."
        ),
    )
    p.add_argument("hprof_file", help="Path to .hprof heap dump")
    p.add_argument("--top", type=int, default=20, help="How many entries to show in each ranking (default: 20)")
    p.add_argument(
        "--workers",
        type=int,
        default=max(1, (os.cpu_count() or 1)),
        help="Worker count for parallel parser/analysis phases (default: CPU count).",
    )
    p.add_argument(
        "--engine",
        choices=("ram", "disk"),
        default="ram",
        help="Graph analysis backend (default: ram). Use disk for lower-memory dominator indexing.",
    )
    p.add_argument(
        "--work-dir",
        default=None,
        help="Directory for disk engine temporary index files (default: system temp directory).",
    )
    p.add_argument(
        "--cache",
        dest="cache",
        action="store_true",
        default=True,
        help="Enable on-disk result cache keyed by file content hash and analysis options (default: enabled).",
    )
    p.add_argument(
        "--no-cache",
        dest="cache",
        action="store_false",
        help="Disable on-disk result cache for this run.",
    )
    p.add_argument(
        "--cache-dir",
        default=".hprof-cache/results",
        help="Directory for cached analysis results (default: .hprof-cache/results).",
    )
    p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--no-dominator",
        action="store_true",
        help="Skip retained-size dominator calculation (faster, only class summary).",
    )
    p.add_argument(
        "--include-unreachable-roots",
        action="store_true",
        help="Treat HPROF ROOT_UNREACHABLE records as roots (off by default).",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Print phase timings and periodic progress updates to stderr.",
    )
    default_max_memory_gb = _default_max_memory_gb()
    if default_max_memory_gb is None:
        memory_help = (
            "Soft memory budget in GiB for dominator edge indexing. "
            "If omitted, no explicit budget is applied."
        )
    else:
        memory_help = (
            "Soft memory budget in GiB for dominator edge indexing "
            f"(default: {default_max_memory_gb}, 60%% of detected RAM)."
        )
    p.add_argument(
        "--max-memory-gb",
        type=int,
        default=default_max_memory_gb,
        help=memory_help,
    )
    return p


def _default_max_memory_gb() -> int | None:
    total_bytes = _detect_total_memory_bytes()
    if total_bytes is None or total_bytes <= 0:
        return None
    gb = int((total_bytes * 0.60) / (1024**3))
    return max(1, gb)


def _detect_total_memory_bytes() -> int | None:
    try:
        import psutil  # type: ignore

        return int(psutil.virtual_memory().total)
    except Exception:
        pass

    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if isinstance(pages, int) and isinstance(page_size, int) and pages > 0 and page_size > 0:
            return pages * page_size
    except Exception:
        pass
    return None


def _print_text(result: AnalysisResult, source: Path) -> None:
    print(f"File: {source}")
    print(f"Objects parsed: {result.object_count:,}")
    print(f"GC roots: {result.root_count:,}")
    print(f"Total shallow heap: {_human_bytes(result.total_shallow_size)}")
    print(
        "Non-collectable shallow heap: "
        f"{_human_bytes(result.non_collectable_size)} "
        f"({result.reachable_count:,} objects reachable from GC roots)"
    )

    print()
    print("Top classes by non-collectable shallow size:")
    _print_class_table(result)

    if result.top_retainers:
        print()
        print("Top object retainers (approximate retained size):")
        _print_retainer_table(result)


def _print_json(result: AnalysisResult, source: str) -> None:
    payload = _analysis_result_to_json_payload(result, source)
    print(json.dumps(payload, indent=2))


def _analysis_result_to_json_payload(result: AnalysisResult, source: str) -> dict:
    return {
        "file": source,
        "object_count": result.object_count,
        "root_count": result.root_count,
        "total_shallow_size": result.total_shallow_size,
        "reachable_count": result.reachable_count,
        "non_collectable_size": result.non_collectable_size,
        "class_summaries": [
            {
                "type_name": row.type_name,
                "object_count": row.object_count,
                "shallow_size": row.shallow_size,
            }
            for row in result.class_summaries
        ],
        "top_retainers": [
            {
                "object_id": f"0x{row.object_id:x}",
                "type_name": row.type_name,
                "shallow_size": row.shallow_size,
                "retained_size": row.retained_size,
                "held_by_object_id": f"0x{row.held_by_object_id:x}" if row.held_by_object_id is not None else None,
                "held_by_type_name": row.held_by_type_name,
                "retainer_chain": [
                    {"object_id": f"0x{node.object_id:x}", "type_name": node.type_name}
                    for node in row.retainer_chain
                ],
                "retainer_chain_truncated": row.retainer_chain_truncated,
            }
            for row in result.top_retainers
        ],
    }


def _cache_file_path(cache_dir: Path, file_hash: str, args: argparse.Namespace) -> Path:
    key_payload = {
        "schema": _CACHE_SCHEMA_VERSION,
        "top": args.top,
        "include_dominator": not args.no_dominator,
        "include_unreachable_roots": args.include_unreachable_roots,
        "engine": args.engine,
        "workers": args.workers,
        "max_memory_gb": args.max_memory_gb,
    }
    key_raw = json.dumps(key_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    key_hash = hashlib.sha256(key_raw).hexdigest()
    return cache_dir / file_hash / f"{key_hash}.json"


def _save_cached_result(path: Path, result: AnalysisResult, *, progress: _ProgressPrinter | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": _CACHE_SCHEMA_VERSION,
        "result": _analysis_result_to_cache_payload(result),
    }
    path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    if progress is not None:
        progress(f"Cache: saved ({path})")


def _load_cached_result(path: Path) -> AnalysisResult | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("schema") != _CACHE_SCHEMA_VERSION:
        return None
    raw_result = payload.get("result")
    if not isinstance(raw_result, dict):
        return None
    try:
        return _analysis_result_from_cache_payload(raw_result)
    except Exception:
        return None


def _analysis_result_to_cache_payload(result: AnalysisResult) -> dict:
    return {
        "object_count": result.object_count,
        "root_count": result.root_count,
        "total_shallow_size": result.total_shallow_size,
        "reachable_count": result.reachable_count,
        "non_collectable_size": result.non_collectable_size,
        "class_summaries": [
            {
                "type_name": row.type_name,
                "object_count": row.object_count,
                "shallow_size": row.shallow_size,
            }
            for row in result.class_summaries
        ],
        "top_retainers": [
            {
                "object_id": row.object_id,
                "type_name": row.type_name,
                "shallow_size": row.shallow_size,
                "retained_size": row.retained_size,
                "held_by_object_id": row.held_by_object_id,
                "held_by_type_name": row.held_by_type_name,
                "retainer_chain": [
                    {"object_id": node.object_id, "type_name": node.type_name}
                    for node in row.retainer_chain
                ],
                "retainer_chain_truncated": row.retainer_chain_truncated,
            }
            for row in result.top_retainers
        ],
    }


def _analysis_result_from_cache_payload(payload: dict) -> AnalysisResult:
    class_summaries = [
        ClassSummary(
            type_name=str(row["type_name"]),
            object_count=int(row["object_count"]),
            shallow_size=int(row["shallow_size"]),
        )
        for row in payload.get("class_summaries", [])
    ]
    top_retainers = []
    for row in payload.get("top_retainers", []):
        chain = [
            RetainerChainNode(
                object_id=int(node["object_id"]),
                type_name=str(node["type_name"]),
            )
            for node in row.get("retainer_chain", [])
        ]
        top_retainers.append(
            RetainerSummary(
                object_id=int(row["object_id"]),
                type_name=str(row["type_name"]),
                shallow_size=int(row["shallow_size"]),
                retained_size=int(row["retained_size"]),
                held_by_object_id=(int(row["held_by_object_id"]) if row.get("held_by_object_id") is not None else None),
                held_by_type_name=str(row["held_by_type_name"]),
                retainer_chain=chain,
                retainer_chain_truncated=bool(row.get("retainer_chain_truncated", False)),
            )
        )
    return AnalysisResult(
        object_count=int(payload["object_count"]),
        root_count=int(payload["root_count"]),
        total_shallow_size=int(payload["total_shallow_size"]),
        reachable_count=int(payload["reachable_count"]),
        non_collectable_size=int(payload["non_collectable_size"]),
        class_summaries=class_summaries,
        top_retainers=top_retainers,
    )


def _get_file_hash_with_index(path: Path, cache_dir: Path, *, progress: _ProgressPrinter | None = None) -> str:
    stat = path.stat()
    abs_path = str(path.resolve())
    index_path = cache_dir / _CACHE_HASH_INDEX
    index: dict[str, dict[str, int | str]] = {}
    if index_path.exists():
        try:
            raw = json.loads(index_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                index = raw
        except Exception:
            index = {}

    cached = index.get(abs_path)
    size = int(stat.st_size)
    mtime_ns = int(stat.st_mtime_ns)
    if isinstance(cached, dict):
        cached_size = int(cached.get("size", -1))
        cached_mtime = int(cached.get("mtime_ns", -1))
        cached_hash = cached.get("sha256")
        if cached_size == size and cached_mtime == mtime_ns and isinstance(cached_hash, str) and cached_hash:
            return cached_hash

    if progress is not None:
        progress(f"Cache: hashing file for key ({path})")
    digest = hashlib.sha256()
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(1024 * 1024 * 8)
            if not chunk:
                break
            digest.update(chunk)
    file_hash = digest.hexdigest()
    index[abs_path] = {"size": size, "mtime_ns": mtime_ns, "sha256": file_hash}
    try:
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text(json.dumps(index, separators=(",", ":")), encoding="utf-8")
    except Exception:
        pass
    return file_hash


def _print_class_table(result: AnalysisResult) -> None:
    if not result.class_summaries:
        print("  (none)")
        return

    rank_w = max(4, len(str(len(result.class_summaries))))
    obj_w = max(7, max(len(f"{row.object_count:,}") for row in result.class_summaries))
    size_w = max(10, max(len(_human_bytes(row.shallow_size)) for row in result.class_summaries))

    print(f"{'#':>{rank_w}}  {'Objects':>{obj_w}}  {'Shallow':>{size_w}}  Type")
    for idx, row in enumerate(result.class_summaries, start=1):
        print(
            f"{idx:>{rank_w}}  "
            f"{row.object_count:>{obj_w},}  "
            f"{_human_bytes(row.shallow_size):>{size_w}}  "
            f"{row.type_name}"
        )


def _print_retainer_table(result: AnalysisResult) -> None:
    rank_w = max(4, len(str(len(result.top_retainers))))
    shallow_w = max(10, max(len(_human_bytes(row.shallow_size)) for row in result.top_retainers))
    retained_w = max(10, max(len(_human_bytes(row.retained_size)) for row in result.top_retainers))

    print(f"{'#':>{rank_w}}  {'Retained':>{retained_w}}  {'Shallow':>{shallow_w}}  {'Object ID':>18}  Type")
    for idx, row in enumerate(result.top_retainers, start=1):
        print(
            f"{idx:>{rank_w}}  "
            f"{_human_bytes(row.retained_size):>{retained_w}}  "
            f"{_human_bytes(row.shallow_size):>{shallow_w}}  "
            f"{f'0x{row.object_id:x}':>18}  "
            f"{row.type_name}"
        )
        if row.held_by_object_id is None:
            held_by = "GC_ROOT"
        else:
            held_by = f"0x{row.held_by_object_id:x} {row.held_by_type_name}"
        print(f"{'':>{rank_w}}  held_by: {held_by}")
        print(f"{'':>{rank_w}}  chain: {_format_retainer_chain(row)}")


def _format_retainer_chain(row) -> str:
    if not row.retainer_chain:
        return "GC_ROOT"
    parts = ["GC_ROOT"]
    for node in row.retainer_chain:
        parts.append(f"0x{node.object_id:x}({node.type_name})")
    if row.retainer_chain_truncated:
        parts.append("...")
    return " -> ".join(parts)


def _human_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    units = ("KiB", "MiB", "GiB", "TiB")
    size = float(value)
    for unit in units:
        size /= 1024.0
        if size < 1024.0:
            return f"{size:.2f} {unit}"
    return f"{size:.2f} PiB"


class _ProgressPrinter:
    def __init__(self) -> None:
        self._start_time = time.perf_counter()

    def __call__(self, message: str) -> None:
        elapsed = time.perf_counter() - self._start_time
        print(f"[{elapsed:7.2f}s] {message}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    sys.exit(main())
