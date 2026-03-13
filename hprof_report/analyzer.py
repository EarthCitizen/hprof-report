from __future__ import annotations

from array import array
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import heapq
import math
from pathlib import Path
import sys
import time
from typing import Callable, Iterable, Protocol, Sequence

from .model import HeapSnapshot, ObjectRecord


@dataclass(slots=True)
class ClassSummary:
    type_name: str
    object_count: int
    shallow_size: int


@dataclass(slots=True)
class RetainerSummary:
    object_id: int
    type_name: str
    shallow_size: int
    retained_size: int
    held_by_object_id: int | None
    held_by_type_name: str
    retainer_chain: list["RetainerChainNode"]
    retainer_chain_truncated: bool


@dataclass(slots=True)
class AnalysisResult:
    object_count: int
    root_count: int
    total_shallow_size: int
    reachable_count: int
    non_collectable_size: int
    class_summaries: list[ClassSummary]
    top_retainers: list[RetainerSummary]


@dataclass(slots=True)
class RetainerChainNode:
    object_id: int
    type_name: str


ProgressCallback = Callable[[str], None]
SUMMARY_PARALLEL_MIN = 200_000


class _Adjacency(Protocol):
    def __len__(self) -> int: ...

    def __getitem__(self, idx: int) -> Sequence[int]: ...


@dataclass(slots=True)
class _DenseReachability:
    node_ids: list[int]
    shallow: list[int]
    reachable_shallow: int
    succ: _Adjacency | None
    pred: _Adjacency | None
    root_idx: int
    cleanup: Callable[[], None] | None


def analyze_snapshot(
    snapshot: HeapSnapshot,
    *,
    top_n: int = 20,
    include_dominator: bool = True,
    engine: str = "ram",
    work_dir: str | Path | None = None,
    workers: int = 1,
    max_memory_gb: int | None = None,
    progress: ProgressCallback | None = None,
) -> AnalysisResult:
    started_at = time.perf_counter()
    objects = snapshot.objects

    if progress is not None:
        progress("Analysis: computing dense reachable graph from GC roots")
    dense = _build_dense_reachability(
        snapshot,
        need_edges=include_dominator,
        engine=engine,
        work_dir=work_dir,
        workers=workers,
        max_memory_gb=max_memory_gb,
        progress=progress,
    )
    try:
        reachable = dense.node_ids
        reachable_shallow = dense.reachable_shallow
        if progress is not None:
            progress(f"Analysis: reachability complete ({len(reachable):,} reachable objects)")

        total_shallow = sum(obj.shallow_size for obj in objects.values())
        if progress is not None:
            progress("Analysis: summarizing top classes by shallow size")
        class_summaries = _summarize_by_type(snapshot, reachable, top_n=top_n, workers=workers, progress=progress)

        if include_dominator and dense.succ is not None and dense.pred is not None:
            if progress is not None:
                progress("Analysis: computing retained sizes via dominator tree")
            top_retainers = _compute_top_retainers(snapshot, dense, top_n=top_n, progress=progress)
        elif include_dominator:
            top_retainers = []
            if progress is not None:
                progress("Analysis: skipping dominator tree (insufficient memory for edge index)")
        else:
            top_retainers = []
            if progress is not None:
                progress("Analysis: skipping dominator tree (--no-dominator)")

        if progress is not None:
            elapsed = time.perf_counter() - started_at
            progress(f"Analysis: complete in {elapsed:.2f}s")

        return AnalysisResult(
            object_count=len(objects),
            root_count=len(snapshot.roots),
            total_shallow_size=total_shallow,
            reachable_count=len(reachable),
            non_collectable_size=reachable_shallow,
            class_summaries=class_summaries,
            top_retainers=top_retainers,
        )
    finally:
        if dense.cleanup is not None:
            dense.cleanup()


def _build_dense_reachability(
    snapshot: HeapSnapshot,
    *,
    need_edges: bool,
    engine: str,
    work_dir: str | Path | None = None,
    workers: int = 1,
    max_memory_gb: int | None = None,
    progress: ProgressCallback | None = None,
) -> _DenseReachability:
    objects = snapshot.objects
    objects_get = objects.__getitem__
    contains = objects.__contains__

    node_ids: list[int] = []
    node_index: dict[int, int] = {}
    stack = [root for root in snapshot.roots if root in objects]
    reachable_shallow = 0

    last_report = time.perf_counter()
    while stack:
        obj_id = stack.pop()
        if obj_id in node_index:
            continue
        node_index[obj_id] = len(node_ids)
        node_ids.append(obj_id)

        obj = objects[obj_id]
        reachable_shallow += obj.shallow_size
        refs = obj.refs
        for ref_id in refs:
            if ref_id not in node_index and contains(ref_id):
                stack.append(ref_id)

        if progress is not None and len(node_ids) % 500_000 == 0:
            now = time.perf_counter()
            if (now - last_report) >= 1.5:
                progress(f"Reachability: visited {len(node_ids):,} objects, frontier={len(stack):,}")
                last_report = now

    n = len(node_ids)
    shallow = [0] * n
    for idx, obj_id in enumerate(node_ids):
        shallow[idx] = objects_get(obj_id).shallow_size

    root_idx = n
    if not need_edges:
        return _DenseReachability(
            node_ids=node_ids,
            shallow=shallow,
            reachable_shallow=reachable_shallow,
            succ=None,
            pred=None,
            root_idx=root_idx,
            cleanup=None,
        )

    if engine == "disk":
        from .disk_graph import build_disk_adjacency

        try:
            store = build_disk_adjacency(
                snapshot,
                node_ids,
                node_index,
                root_idx,
                work_dir=work_dir,
                workers=workers,
                progress=progress,
            )
        except MemoryError:
            if progress is not None:
                progress("Analysis: out of memory building disk-backed edge index; continuing without dominator")
            return _DenseReachability(
                node_ids=node_ids,
                shallow=shallow,
                reachable_shallow=reachable_shallow,
                succ=None,
                pred=None,
                root_idx=root_idx,
                cleanup=None,
            )
        return _DenseReachability(
            node_ids=node_ids,
            shallow=shallow,
            reachable_shallow=reachable_shallow,
            succ=store.succ,
            pred=store.pred,
            root_idx=root_idx,
            cleanup=store.close,
        )

    if engine != "ram":
        raise ValueError(f"Unsupported engine: {engine}")

    if max_memory_gb is not None and max_memory_gb > 0:
        budget_bytes = max_memory_gb * (1024**3)
        baseline_bytes = _estimate_dense_edge_index_baseline_bytes(n + 1)
        if baseline_bytes > budget_bytes:
            if progress is not None:
                progress(
                    "Analysis: skipping dominator tree "
                    f"(edge index baseline {baseline_bytes / (1024**3):.2f} GiB "
                    f"exceeds --max-memory-gb={max_memory_gb})"
                )
            return _DenseReachability(
                node_ids=node_ids,
                shallow=shallow,
                reachable_shallow=reachable_shallow,
                succ=None,
                pred=None,
                root_idx=root_idx,
                cleanup=None,
            )

    try:
        succ, pred = _allocate_adjacency_lists(n + 1)
        node_index_get = node_index.get
        for idx, obj_id in enumerate(node_ids):
            obj = objects_get(obj_id)
            row = succ[idx]
            row_append = row.append
            for ref_id in obj.refs:
                target = node_index_get(ref_id)
                if target is not None:
                    row_append(target)
                    pred[target].append(idx)

        root_row = succ[root_idx]
        root_row_append = root_row.append
        for root_obj_id in snapshot.roots:
            idx = node_index_get(root_obj_id)
            if idx is not None:
                root_row_append(idx)
                pred[idx].append(root_idx)
    except MemoryError:
        if progress is not None:
            progress("Analysis: out of memory building dominator edge index; continuing without dominator")
        return _DenseReachability(
            node_ids=node_ids,
            shallow=shallow,
            reachable_shallow=reachable_shallow,
            succ=None,
            pred=None,
            root_idx=root_idx,
            cleanup=None,
        )

    return _DenseReachability(
        node_ids=node_ids,
        shallow=shallow,
        reachable_shallow=reachable_shallow,
        succ=succ,
        pred=pred,
        root_idx=root_idx,
        cleanup=None,
    )


def _summarize_by_type(
    snapshot: HeapSnapshot,
    reachable: Iterable[int],
    *,
    top_n: int,
    workers: int,
    progress: ProgressCallback | None = None,
) -> list[ClassSummary]:
    reachable_ids = reachable if isinstance(reachable, list) else list(reachable)
    if workers <= 1 or len(reachable_ids) < SUMMARY_PARALLEL_MIN:
        counts, sizes = _summarize_type_chunk(snapshot, reachable_ids)
    else:
        max_workers = max(1, int(workers))
        chunk_size = max(100_000, math.ceil(len(reachable_ids) / max_workers))
        ranges: list[tuple[int, int]] = []
        start = 0
        while start < len(reachable_ids):
            end = min(len(reachable_ids), start + chunk_size)
            ranges.append((start, end))
            start = end

        if progress is not None:
            progress(f"Analysis: class summary using {max_workers} workers")

        counts = {}
        sizes = {}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(_summarize_type_chunk, snapshot, reachable_ids[start:end]) for start, end in ranges]
            for fut in futures:
                chunk_counts, chunk_sizes = fut.result()
                for type_name, count in chunk_counts.items():
                    counts[type_name] = counts.get(type_name, 0) + count
                for type_name, shallow in chunk_sizes.items():
                    sizes[type_name] = sizes.get(type_name, 0) + shallow

    summaries = [
        ClassSummary(type_name=type_name, object_count=counts[type_name], shallow_size=shallow)
        for type_name, shallow in sizes.items()
    ]
    summaries.sort(key=lambda it: it.shallow_size, reverse=True)
    return summaries[:top_n]


def _summarize_type_chunk(
    snapshot: HeapSnapshot,
    reachable_ids: Sequence[int],
) -> tuple[dict[str, int], dict[str, int]]:
    objects = snapshot.objects
    counts: dict[str, int] = {}
    sizes: dict[str, int] = {}
    type_name_cache: dict[tuple[str, int | None, str | None], str] = {}

    for obj_id in reachable_ids:
        obj = objects[obj_id]
        type_name = _cached_object_type_name(snapshot, obj, type_name_cache)
        counts[type_name] = counts.get(type_name, 0) + 1
        sizes[type_name] = sizes.get(type_name, 0) + obj.shallow_size

    return counts, sizes


def _allocate_adjacency_lists(size: int) -> tuple[list[list[int]], list[list[int]]]:
    return ([[] for _ in range(size)], [[] for _ in range(size)])


def _estimate_dense_edge_index_baseline_bytes(size: int) -> int:
    empty_list = sys.getsizeof([])
    one_item_list = sys.getsizeof([0])
    ptr_size = max(0, one_item_list - empty_list)

    # Approximate lower bound for two list-of-lists structures:
    # - outer list storage (list headers + element pointer arrays)
    # - per-node empty row list headers
    outer_lists = 2 * (empty_list + (size * ptr_size))
    per_row_lists = 2 * size * empty_list
    return outer_lists + per_row_lists


def _compute_top_retainers(
    snapshot: HeapSnapshot,
    dense: _DenseReachability,
    *,
    top_n: int,
    progress: ProgressCallback | None = None,
) -> list[RetainerSummary]:
    if not dense.node_ids:
        return []

    objects = snapshot.objects
    node_ids = dense.node_ids
    n = len(node_ids)
    root_idx = dense.root_idx
    succ = dense.succ
    pred = dense.pred
    if succ is None or pred is None:
        return []

    shallow = dense.shallow + [0]
    idom_result = _compute_idom_lengauer_tarjan(succ, pred, root_idx, progress=progress)
    if idom_result is None:
        return []
    idom, dfs_order = idom_result

    retained = shallow[:]
    if progress is not None:
        progress("Dominator: accumulating retained sizes")
    last_report = time.perf_counter()
    processed = 0
    for node in reversed(dfs_order[1:]):  # Exclude synthetic root from the child-to-parent roll-up loop.
        parent = idom[node]
        if parent != -1 and parent != node:
            retained[parent] += retained[node]
        processed += 1
        if progress is not None and processed % 500_000 == 0:
            now = time.perf_counter()
            if (now - last_report) >= 1.5:
                progress(f"Dominator: retained accumulation {processed:,}/{len(dfs_order) - 1:,}")
                last_report = now

    top_indexes = heapq.nlargest(min(top_n, n), range(n), key=retained.__getitem__)
    type_name_cache: dict[tuple[str, int | None, str | None], str] = {}
    out: list[RetainerSummary] = []
    for idx in top_indexes:
        obj_id = node_ids[idx]
        obj = objects[obj_id]
        held_by_object_id: int | None
        held_by_type_name: str
        parent_idx = idom[idx]
        if parent_idx == root_idx or parent_idx == -1:
            held_by_object_id = None
            held_by_type_name = "GC_ROOT"
        else:
            held_by_object_id = node_ids[parent_idx]
            held_by_type_name = _cached_object_type_name(snapshot, objects[held_by_object_id], type_name_cache)

        chain_nodes, chain_truncated = _build_retainer_chain(
            idx=idx,
            idom=idom,
            node_ids=node_ids,
            root_idx=root_idx,
            objects=objects,
            snapshot=snapshot,
            type_name_cache=type_name_cache,
        )
        out.append(
            RetainerSummary(
                object_id=obj_id,
                type_name=_cached_object_type_name(snapshot, obj, type_name_cache),
                shallow_size=shallow[idx],
                retained_size=retained[idx],
                held_by_object_id=held_by_object_id,
                held_by_type_name=held_by_type_name,
                retainer_chain=chain_nodes,
                retainer_chain_truncated=chain_truncated,
            )
        )
    if progress is not None:
        progress("Dominator: retained-size ranking complete")
    return out


def _compute_idom_lengauer_tarjan(
    succ: _Adjacency,
    pred: _Adjacency,
    root_idx: int,
    *,
    progress: ProgressCallback | None = None,
) -> tuple[Sequence[int], list[int]] | None:
    node_count = len(succ)

    parent = array("i", [-1]) * node_count
    ancestor = array("i", [-1]) * node_count
    label = array("i", [-1]) * node_count
    idom = array("i", [-1]) * node_count
    dfsnum = array("I", [0]) * node_count
    semi = array("I", [0]) * node_count

    # vertex[dfs_index] -> node index. Index 0 is unused to keep DFS numbers 1-based.
    vertex = array("i", [0])
    dfs_index = 0

    stack: list[tuple[int, int]] = [(root_idx, 0)]
    dfs_index += 1
    dfsnum[root_idx] = dfs_index
    semi[root_idx] = dfs_index
    label[root_idx] = root_idx
    vertex.append(root_idx)

    last_report = time.perf_counter()
    while stack:
        node, edge_pos = stack[-1]
        row = succ[node]
        if edge_pos < len(row):
            nxt = int(row[edge_pos])
            stack[-1] = (node, edge_pos + 1)
            if dfsnum[nxt] != 0:
                continue
            parent[nxt] = node
            dfs_index += 1
            dfsnum[nxt] = dfs_index
            semi[nxt] = dfs_index
            label[nxt] = nxt
            vertex.append(nxt)
            stack.append((nxt, 0))
            if progress is not None and dfs_index % 500_000 == 0:
                now = time.perf_counter()
                if (now - last_report) >= 1.5:
                    progress(f"Dominator: DFS discovered {dfs_index - 1:,} nodes")
                    last_report = now
            continue
        stack.pop()

    if dfs_index == 0:
        return None

    if progress is not None:
        progress(f"Dominator: DFS order built ({dfs_index - 1:,} nodes)")

    def lt_link(v: int, w: int) -> None:
        ancestor[w] = v

    def lt_compress(v: int) -> None:
        av = ancestor[v]
        if av == -1:
            return
        aav = ancestor[av]
        if aav != -1:
            lt_compress(av)
            lav = label[av]
            if semi[lav] < semi[label[v]]:
                label[v] = lav
            ancestor[v] = ancestor[av]

    def lt_eval(v: int) -> int:
        if ancestor[v] == -1:
            return label[v]
        lt_compress(v)
        return label[v]

    buckets: dict[int, list[int]] = {}
    last_report = time.perf_counter()
    processed = 0
    for idx in range(dfs_index, 1, -1):
        w = vertex[idx]
        sw = semi[w]
        for pred_node_raw in pred[w]:
            pred_node = int(pred_node_raw)
            if dfsnum[pred_node] == 0:
                continue
            u = lt_eval(pred_node)
            if semi[u] < sw:
                sw = semi[u]
        semi[w] = sw

        semidom_node = vertex[sw]
        bucket = buckets.get(semidom_node)
        if bucket is None:
            buckets[semidom_node] = [w]
        else:
            bucket.append(w)

        pw = parent[w]
        lt_link(pw, w)

        pw_bucket = buckets.pop(pw, None)
        if pw_bucket is not None:
            for v in pw_bucket:
                u = lt_eval(v)
                if semi[u] < semi[v]:
                    idom[v] = u
                else:
                    idom[v] = pw

        processed += 1
        if progress is not None and processed % 500_000 == 0:
            now = time.perf_counter()
            if (now - last_report) >= 1.5:
                progress(f"Dominator: semidominators processed {processed:,}/{dfs_index - 1:,}")
                last_report = now

    idom[root_idx] = root_idx
    for idx in range(2, dfs_index + 1):
        w = vertex[idx]
        sw_node = vertex[semi[w]]
        iw = idom[w]
        if iw == -1:
            continue
        if iw != sw_node:
            idom[w] = idom[iw]

    return idom, [int(node) for node in vertex[1 : dfs_index + 1]]


def _cached_object_type_name(
    snapshot: HeapSnapshot,
    obj: ObjectRecord,
    cache: dict[tuple[str, int | None, str | None], str],
) -> str:
    key = (obj.kind, obj.class_id, obj.display_type)
    name = cache.get(key)
    if name is not None:
        return name
    name = snapshot.object_type_name(obj)
    cache[key] = name
    return name


def _build_retainer_chain(
    *,
    idx: int,
    idom: Sequence[int],
    node_ids: list[int],
    root_idx: int,
    objects: dict[int, ObjectRecord],
    snapshot: HeapSnapshot,
    type_name_cache: dict[tuple[str, int | None, str | None], str],
    max_depth: int = 32,
) -> tuple[list[RetainerChainNode], bool]:
    chain_ids: list[int] = []
    current = idx
    depth = 0
    truncated = False
    while current != root_idx and current != -1:
        chain_ids.append(node_ids[current])
        current = idom[current]
        depth += 1
        if depth >= max_depth:
            if current not in (root_idx, -1):
                truncated = True
            break

    chain_ids.reverse()
    chain_nodes = [
        RetainerChainNode(
            object_id=obj_id,
            type_name=_cached_object_type_name(snapshot, objects[obj_id], type_name_cache),
        )
        for obj_id in chain_ids
    ]
    return chain_nodes, truncated
