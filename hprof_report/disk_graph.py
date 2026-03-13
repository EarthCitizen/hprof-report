from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import math
from pathlib import Path
import shutil
import tempfile
import time
from typing import Callable

from .model import HeapSnapshot


ProgressCallback = Callable[[str], None]
CSR_PARALLEL_MIN = 200_000


class MemmapAdjacency:
    def __init__(self, offsets, targets) -> None:
        self._offsets = offsets
        self._targets = targets
        self._rows = len(offsets) - 1

    def __len__(self) -> int:
        return self._rows

    def __getitem__(self, idx: int):
        start = int(self._offsets[idx])
        end = int(self._offsets[idx + 1])
        return self._targets[start:end]


@dataclass(slots=True)
class DiskAdjacencyStore:
    succ: MemmapAdjacency
    pred: MemmapAdjacency
    base_dir: Path
    _arrays: list
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        for arr in self._arrays:
            _close_array(arr)
        self._arrays.clear()
        shutil.rmtree(self.base_dir, ignore_errors=True)
        self._closed = True


def build_disk_adjacency(
    snapshot: HeapSnapshot,
    node_ids: list[int],
    node_index: dict[int, int],
    root_idx: int,
    *,
    work_dir: str | Path | None = None,
    workers: int = 1,
    progress: ProgressCallback | None = None,
) -> DiskAdjacencyStore:
    try:
        import numpy as np
    except Exception as exc:
        raise RuntimeError("engine=disk requires numpy. Install dependencies from requirements.txt.") from exc

    started_at = time.perf_counter()
    objects = snapshot.objects
    objects_get = objects.__getitem__
    node_index_get = node_index.get
    row_count = len(node_ids) + 1

    if work_dir is None:
        base_dir = Path(tempfile.mkdtemp(prefix="hprof-report-"))
    else:
        parent = Path(work_dir)
        parent.mkdir(parents=True, exist_ok=True)
        base_dir = Path(tempfile.mkdtemp(prefix="hprof-report-", dir=str(parent)))

    if progress is not None:
        progress(f"Disk graph: building CSR files in {base_dir}")

    out_counts = np.zeros(row_count, dtype=np.uint32)
    in_counts = np.zeros(row_count, dtype=np.uint32)

    last_report = time.perf_counter()
    for idx, obj_id in enumerate(node_ids):
        obj = objects_get(obj_id)
        for ref_id in obj.refs:
            target = node_index_get(ref_id)
            if target is not None:
                out_counts[idx] += 1
                in_counts[target] += 1

        if progress is not None and idx % 500_000 == 0 and idx > 0:
            now = time.perf_counter()
            if (now - last_report) >= 1.5:
                progress(f"Disk graph: counted edges for {idx:,}/{len(node_ids):,} nodes")
                last_report = now

    root_out = 0
    for root_obj_id in snapshot.roots:
        idx = node_index_get(root_obj_id)
        if idx is not None:
            root_out += 1
            in_counts[idx] += 1
    out_counts[root_idx] = root_out

    succ_offsets = np.memmap(base_dir / "succ_offsets.bin", dtype=np.uint64, mode="w+", shape=(row_count + 1,))
    pred_offsets = np.memmap(base_dir / "pred_offsets.bin", dtype=np.uint64, mode="w+", shape=(row_count + 1,))
    succ_offsets[0] = 0
    pred_offsets[0] = 0
    np.cumsum(out_counts, dtype=np.uint64, out=succ_offsets[1:])
    np.cumsum(in_counts, dtype=np.uint64, out=pred_offsets[1:])
    total_edges = int(succ_offsets[-1])

    succ_targets = _create_targets_array(np, base_dir / "succ_targets.bin", total_edges)
    pred_targets = _create_targets_array(np, base_dir / "pred_targets.bin", total_edges)

    parallel_workers = max(1, int(workers))
    if parallel_workers > 1 and len(node_ids) >= CSR_PARALLEL_MIN:
        if progress is not None:
            progress(f"Disk graph: materializing successor edges with {parallel_workers} workers")
        _fill_successors_parallel(
            node_ids=node_ids,
            objects_get=objects_get,
            node_index_get=node_index_get,
            succ_offsets=succ_offsets,
            succ_targets=succ_targets,
            worker_count=parallel_workers,
            progress=progress,
        )
        # Add synthetic-root successor edges after worker fill.
        root_write_pos = int(succ_offsets[root_idx])
        for root_obj_id in snapshot.roots:
            idx = node_index_get(root_obj_id)
            if idx is None:
                continue
            succ_targets[root_write_pos] = idx
            root_write_pos += 1

        if progress is not None:
            progress("Disk graph: building predecessor index from successors")
        pred_cursor = np.memmap(base_dir / "pred_cursor.bin", dtype=np.uint64, mode="w+", shape=(row_count,))
        pred_cursor[:] = pred_offsets[:-1]

        last_report = time.perf_counter()
        for src in range(row_count):
            start = int(succ_offsets[src])
            end = int(succ_offsets[src + 1])
            for edge_pos in range(start, end):
                target = int(succ_targets[edge_pos])
                pred_pos = int(pred_cursor[target])
                pred_targets[pred_pos] = src
                pred_cursor[target] = pred_pos + 1

            if progress is not None and src % 500_000 == 0 and src > 0:
                now = time.perf_counter()
                if (now - last_report) >= 1.5:
                    progress(f"Disk graph: predecessor build {src:,}/{row_count:,} rows")
                    last_report = now

        _close_array(pred_cursor)
        (base_dir / "pred_cursor.bin").unlink(missing_ok=True)
    else:
        succ_cursor = np.memmap(base_dir / "succ_cursor.bin", dtype=np.uint64, mode="w+", shape=(row_count,))
        pred_cursor = np.memmap(base_dir / "pred_cursor.bin", dtype=np.uint64, mode="w+", shape=(row_count,))
        succ_cursor[:] = succ_offsets[:-1]
        pred_cursor[:] = pred_offsets[:-1]

        last_report = time.perf_counter()
        for idx, obj_id in enumerate(node_ids):
            obj = objects_get(obj_id)
            for ref_id in obj.refs:
                target = node_index_get(ref_id)
                if target is None:
                    continue
                succ_pos = int(succ_cursor[idx])
                pred_pos = int(pred_cursor[target])
                succ_targets[succ_pos] = target
                pred_targets[pred_pos] = idx
                succ_cursor[idx] = succ_pos + 1
                pred_cursor[target] = pred_pos + 1

            if progress is not None and idx % 500_000 == 0 and idx > 0:
                now = time.perf_counter()
                if (now - last_report) >= 1.5:
                    progress(f"Disk graph: materialized edges for {idx:,}/{len(node_ids):,} nodes")
                    last_report = now

        for root_obj_id in snapshot.roots:
            idx = node_index_get(root_obj_id)
            if idx is None:
                continue
            succ_pos = int(succ_cursor[root_idx])
            pred_pos = int(pred_cursor[idx])
            succ_targets[succ_pos] = idx
            pred_targets[pred_pos] = root_idx
            succ_cursor[root_idx] = succ_pos + 1
            pred_cursor[idx] = pred_pos + 1

        _close_array(succ_cursor)
        _close_array(pred_cursor)
        (base_dir / "succ_cursor.bin").unlink(missing_ok=True)
        (base_dir / "pred_cursor.bin").unlink(missing_ok=True)

    succ_offsets.flush()
    pred_offsets.flush()
    if hasattr(succ_targets, "flush"):
        succ_targets.flush()
    if hasattr(pred_targets, "flush"):
        pred_targets.flush()

    store = DiskAdjacencyStore(
        succ=MemmapAdjacency(succ_offsets, succ_targets),
        pred=MemmapAdjacency(pred_offsets, pred_targets),
        base_dir=base_dir,
        _arrays=[succ_offsets, pred_offsets, succ_targets, pred_targets],
    )

    if progress is not None:
        elapsed = time.perf_counter() - started_at
        progress(f"Disk graph: CSR build complete in {elapsed:.2f}s ({total_edges:,} edges)")
    return store


def _create_targets_array(np, path: Path, total_edges: int):
    if total_edges == 0:
        return np.empty((0,), dtype=np.uint32)
    return np.memmap(path, dtype=np.uint32, mode="w+", shape=(total_edges,))


def _fill_successors_parallel(
    *,
    node_ids: list[int],
    objects_get,
    node_index_get,
    succ_offsets,
    succ_targets,
    worker_count: int,
    progress: ProgressCallback | None = None,
) -> None:
    total = len(node_ids)
    if total == 0:
        return
    chunk_size = max(100_000, math.ceil(total / worker_count))

    def worker(start: int, end: int, worker_id: int) -> None:
        if progress is not None:
            progress(f"DiskCSR worker={worker_id}: start rows {start:,}-{end - 1:,}")
        for idx in range(start, end):
            obj = objects_get(node_ids[idx])
            write_pos = int(succ_offsets[idx])
            for ref_id in obj.refs:
                target = node_index_get(ref_id)
                if target is not None:
                    succ_targets[write_pos] = target
                    write_pos += 1
        if progress is not None:
            progress(f"DiskCSR worker={worker_id}: done")

    ranges: list[tuple[int, int]] = []
    start = 0
    while start < total:
        end = min(total, start + chunk_size)
        ranges.append((start, end))
        start = end

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = [pool.submit(worker, start, end, worker_id) for worker_id, (start, end) in enumerate(ranges, start=1)]
        for fut in futures:
            fut.result()


def _close_array(arr) -> None:
    flush = getattr(arr, "flush", None)
    if callable(flush):
        flush()
    mmap_obj = getattr(arr, "_mmap", None)
    if mmap_obj is not None:
        mmap_obj.close()
