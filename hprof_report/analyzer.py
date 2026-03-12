from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .model import HeapSnapshot


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


@dataclass(slots=True)
class AnalysisResult:
    object_count: int
    root_count: int
    total_shallow_size: int
    reachable_count: int
    non_collectable_size: int
    class_summaries: list[ClassSummary]
    top_retainers: list[RetainerSummary]


def analyze_snapshot(
    snapshot: HeapSnapshot,
    *,
    top_n: int = 20,
    include_dominator: bool = True,
) -> AnalysisResult:
    reachable = _compute_reachable(snapshot)

    total_shallow = sum(obj.shallow_size for obj in snapshot.objects.values())
    reachable_shallow = sum(snapshot.objects[obj_id].shallow_size for obj_id in reachable)
    class_summaries = _summarize_by_type(snapshot, reachable, top_n=top_n)
    top_retainers = _compute_top_retainers(snapshot, reachable, top_n=top_n) if include_dominator else []

    return AnalysisResult(
        object_count=len(snapshot.objects),
        root_count=len(snapshot.roots),
        total_shallow_size=total_shallow,
        reachable_count=len(reachable),
        non_collectable_size=reachable_shallow,
        class_summaries=class_summaries,
        top_retainers=top_retainers,
    )


def _compute_reachable(snapshot: HeapSnapshot) -> set[int]:
    reachable: set[int] = set()
    stack = [root for root in snapshot.roots if root in snapshot.objects]
    while stack:
        obj_id = stack.pop()
        if obj_id in reachable:
            continue
        reachable.add(obj_id)
        refs = snapshot.objects[obj_id].refs
        for ref_id in refs:
            if ref_id in snapshot.objects and ref_id not in reachable:
                stack.append(ref_id)
    return reachable


def _summarize_by_type(snapshot: HeapSnapshot, reachable: Iterable[int], *, top_n: int) -> list[ClassSummary]:
    counts: dict[str, int] = {}
    sizes: dict[str, int] = {}

    for obj_id in reachable:
        obj = snapshot.objects[obj_id]
        type_name = snapshot.object_type_name(obj)
        counts[type_name] = counts.get(type_name, 0) + 1
        sizes[type_name] = sizes.get(type_name, 0) + obj.shallow_size

    summaries = [
        ClassSummary(type_name=type_name, object_count=counts[type_name], shallow_size=size)
        for type_name, size in sizes.items()
    ]
    summaries.sort(key=lambda it: it.shallow_size, reverse=True)
    return summaries[:top_n]


def _compute_top_retainers(
    snapshot: HeapSnapshot,
    reachable: set[int],
    *,
    top_n: int,
) -> list[RetainerSummary]:
    if not reachable:
        return []

    node_ids = list(reachable)
    node_index = {obj_id: idx for idx, obj_id in enumerate(node_ids)}
    n = len(node_ids)
    root_idx = n

    succ: list[list[int]] = [[] for _ in range(n + 1)]
    pred: list[list[int]] = [[] for _ in range(n + 1)]
    shallow = [0] * (n + 1)
    for idx, obj_id in enumerate(node_ids):
        obj = snapshot.objects[obj_id]
        shallow[idx] = obj.shallow_size
        for ref_id in obj.refs:
            ref_idx = node_index.get(ref_id)
            if ref_idx is None:
                continue
            succ[idx].append(ref_idx)
            pred[ref_idx].append(idx)

    for root_obj_id in snapshot.roots:
        idx = node_index.get(root_obj_id)
        if idx is None:
            continue
        succ[root_idx].append(idx)
        pred[idx].append(root_idx)

    rpo = _reverse_postorder(succ, root_idx)
    if len(rpo) <= 1:
        return []
    rpo_index = {node: i for i, node in enumerate(rpo)}

    idom = [-1] * (n + 1)
    idom[root_idx] = root_idx

    changed = True
    while changed:
        changed = False
        for node in rpo[1:]:
            preds = [p for p in pred[node] if idom[p] != -1]
            if not preds:
                continue
            new_idom = preds[0]
            for p in preds[1:]:
                new_idom = _intersect(p, new_idom, idom, rpo_index)
            if idom[node] != new_idom:
                idom[node] = new_idom
                changed = True

    children: list[list[int]] = [[] for _ in range(n + 1)]
    for node in range(n):
        parent = idom[node]
        if parent != -1 and parent != node:
            children[parent].append(node)

    retained = [0] * (n + 1)
    tree_postorder = _tree_postorder(children, root_idx)
    for node in tree_postorder:
        total = shallow[node]
        for child in children[node]:
            total += retained[child]
        retained[node] = total

    summaries = []
    for idx, obj_id in enumerate(node_ids):
        obj = snapshot.objects[obj_id]
        summaries.append(
            RetainerSummary(
                object_id=obj_id,
                type_name=snapshot.object_type_name(obj),
                shallow_size=shallow[idx],
                retained_size=retained[idx],
            )
        )
    summaries.sort(key=lambda it: it.retained_size, reverse=True)
    return summaries[:top_n]


def _reverse_postorder(succ: list[list[int]], root_idx: int) -> list[int]:
    visited = [False] * len(succ)
    postorder: list[int] = []
    stack: list[tuple[int, int]] = [(root_idx, 0)]
    visited[root_idx] = True

    while stack:
        node, edge_pos = stack[-1]
        if edge_pos < len(succ[node]):
            nxt = succ[node][edge_pos]
            stack[-1] = (node, edge_pos + 1)
            if not visited[nxt]:
                visited[nxt] = True
                stack.append((nxt, 0))
            continue
        postorder.append(node)
        stack.pop()

    postorder.reverse()
    return postorder


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


def _intersect(a: int, b: int, idom: list[int], rpo_index: dict[int, int]) -> int:
    while a != b:
        while rpo_index[a] > rpo_index[b]:
            a = idom[a]
        while rpo_index[b] > rpo_index[a]:
            b = idom[b]
    return a

