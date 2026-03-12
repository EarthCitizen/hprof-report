from __future__ import annotations

from dataclasses import dataclass
import heapq
import time
from typing import Callable, Iterable

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


@dataclass(slots=True)
class _DenseReachability:
    node_ids: list[int]
    shallow: list[int]
    reachable_shallow: int
    succ: list[list[int]] | None
    pred: list[list[int]] | None
    root_idx: int


def analyze_snapshot(
    snapshot: HeapSnapshot,
    *,
    top_n: int = 20,
    include_dominator: bool = True,
    progress: ProgressCallback | None = None,
) -> AnalysisResult:
    started_at = time.perf_counter()
    objects = snapshot.objects

    if progress is not None:
        progress("Analysis: computing dense reachable graph from GC roots")
    dense = _build_dense_reachability(snapshot, need_edges=include_dominator, progress=progress)
    reachable = dense.node_ids
    reachable_shallow = dense.reachable_shallow
    if progress is not None:
        progress(f"Analysis: reachability complete ({len(reachable):,} reachable objects)")

    total_shallow = sum(obj.shallow_size for obj in objects.values())
    if progress is not None:
        progress("Analysis: summarizing top classes by shallow size")
    class_summaries = _summarize_by_type(snapshot, reachable, top_n=top_n)

    if include_dominator:
        if progress is not None:
            progress("Analysis: computing retained sizes via dominator tree")
        top_retainers = _compute_top_retainers(snapshot, dense, top_n=top_n, progress=progress)
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


def _build_dense_reachability(
    snapshot: HeapSnapshot,
    *,
    need_edges: bool,
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
        )

    succ: list[list[int]] = [[] for _ in range(n + 1)]
    pred: list[list[int]] = [[] for _ in range(n + 1)]
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

    return _DenseReachability(
        node_ids=node_ids,
        shallow=shallow,
        reachable_shallow=reachable_shallow,
        succ=succ,
        pred=pred,
        root_idx=root_idx,
    )


def _summarize_by_type(snapshot: HeapSnapshot, reachable: Iterable[int], *, top_n: int) -> list[ClassSummary]:
    objects = snapshot.objects
    counts: dict[str, int] = {}
    sizes: dict[str, int] = {}
    type_name_cache: dict[tuple[str, int | None, str | None], str] = {}

    for obj_id in reachable:
        obj = objects[obj_id]
        type_name = _cached_object_type_name(snapshot, obj, type_name_cache)
        counts[type_name] = counts.get(type_name, 0) + 1
        sizes[type_name] = sizes.get(type_name, 0) + obj.shallow_size

    summaries = [
        ClassSummary(type_name=type_name, object_count=counts[type_name], shallow_size=shallow)
        for type_name, shallow in sizes.items()
    ]
    summaries.sort(key=lambda it: it.shallow_size, reverse=True)
    return summaries[:top_n]


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
    idom = _compute_idom_iterative(succ, pred, root_idx, progress=progress)
    if idom is None:
        return []

    children: list[list[int]] = [[] for _ in range(n + 1)]
    for node in range(n):
        parent = idom[node]
        if parent != -1 and parent != node:
            children[parent].append(node)

    if progress is not None:
        progress("Dominator: accumulating retained sizes")
    retained = [0] * (n + 1)
    for node in _tree_postorder(children, root_idx):
        total = shallow[node]
        for child in children[node]:
            total += retained[child]
        retained[node] = total

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


def _compute_idom_iterative(
    succ: list[list[int]],
    pred: list[list[int]],
    root_idx: int,
    *,
    progress: ProgressCallback | None = None,
) -> list[int] | None:
    node_count = len(succ)
    rpo = _reverse_postorder(succ, root_idx)
    if len(rpo) <= 1:
        idom = [-1] * node_count
        idom[root_idx] = root_idx
        return idom

    rpo_pos = [0] * node_count
    for i, node in enumerate(rpo):
        rpo_pos[node] = i

    idom = [-1] * node_count
    idom[root_idx] = root_idx

    if progress is not None:
        progress(f"Dominator: traversal order built ({len(rpo) - 1:,} nodes)")

    changed = True
    iteration = 0
    last_report = time.perf_counter()
    while changed:
        iteration += 1
        changed = False
        processed = 0
        for node in rpo[1:]:
            new_idom = -1
            for p in pred[node]:
                if idom[p] == -1:
                    continue
                if new_idom == -1:
                    new_idom = p
                else:
                    new_idom = _intersect(p, new_idom, idom, rpo_pos)

            if new_idom != -1 and idom[node] != new_idom:
                idom[node] = new_idom
                changed = True

            processed += 1
            if progress is not None and processed % 500_000 == 0:
                now = time.perf_counter()
                if (now - last_report) >= 1.5:
                    progress(f"Dominator: iteration {iteration} processed {processed:,}/{len(rpo) - 1:,}")
                    last_report = now

        if progress is not None:
            progress(f"Dominator: iteration {iteration} complete ({'changed' if changed else 'stable'})")

    return idom


def _reverse_postorder(succ: list[list[int]], root_idx: int) -> list[int]:
    visited = [False] * len(succ)
    postorder: list[int] = []
    stack: list[tuple[int, int]] = [(root_idx, 0)]
    visited[root_idx] = True

    while stack:
        node, edge_pos = stack[-1]
        row = succ[node]
        if edge_pos < len(row):
            nxt = row[edge_pos]
            stack[-1] = (node, edge_pos + 1)
            if not visited[nxt]:
                visited[nxt] = True
                stack.append((nxt, 0))
            continue
        postorder.append(node)
        stack.pop()

    postorder.reverse()
    return postorder


def _intersect(a: int, b: int, idom: list[int], rpo_pos: list[int]) -> int:
    while a != b:
        while rpo_pos[a] > rpo_pos[b]:
            a = idom[a]
        while rpo_pos[b] > rpo_pos[a]:
            b = idom[b]
    return a


def _tree_postorder(children: list[list[int]], root_idx: int) -> list[int]:
    postorder: list[int] = []
    stack: list[tuple[int, int]] = [(root_idx, 0)]
    while stack:
        node, child_pos = stack[-1]
        if child_pos < len(children[node]):
            child = children[node][child_pos]
            stack[-1] = (node, child_pos + 1)
            stack.append((child, 0))
            continue
        postorder.append(node)
        stack.pop()
    return postorder


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
    idom: list[int],
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
