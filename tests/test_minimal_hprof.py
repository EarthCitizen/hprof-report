from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest

from hprof_report.analyzer import analyze_snapshot
from hprof_report.model import HeapSnapshot
from hprof_report.parser import HprofParser


def _u1(v: int) -> bytes:
    return struct.pack(">B", v)


def _u2(v: int) -> bytes:
    return struct.pack(">H", v)


def _u4(v: int) -> bytes:
    return struct.pack(">I", v)


def _u8(v: int) -> bytes:
    return struct.pack(">Q", v)


def _id(v: int) -> bytes:
    return _u4(v)


def _record(tag: int, body: bytes) -> bytes:
    return _u1(tag) + _u4(0) + _u4(len(body)) + body


def _string_record(string_id: int, text: str) -> bytes:
    body = _id(string_id) + text.encode("utf-8")
    return _record(0x01, body)


def _load_class_record(class_object_id: int, class_name_string_id: int) -> bytes:
    body = _u4(1) + _id(class_object_id) + _u4(0) + _id(class_name_string_id)
    return _record(0x02, body)


def _class_dump(class_id: int, field_name_id: int) -> bytes:
    return (
        _u1(0x20)
        + _id(class_id)
        + _u4(0)
        + _id(0)
        + _id(0)
        + _id(0)
        + _id(0)
        + _id(0)
        + _id(0)
        + _u4(4)
        + _u2(0)
        + _u2(0)
        + _u2(1)
        + _id(field_name_id)
        + _u1(2)
    )


def _class_dump_no_fields(class_id: int) -> bytes:
    return (
        _u1(0x20)
        + _id(class_id)
        + _u4(0)
        + _id(0)
        + _id(0)
        + _id(0)
        + _id(0)
        + _id(0)
        + _id(0)
        + _u4(0)
        + _u2(0)
        + _u2(0)
        + _u2(0)
    )


def _instance_dump(object_id: int, class_id: int, ref: int) -> bytes:
    return _u1(0x21) + _id(object_id) + _u4(0) + _id(class_id) + _u4(4) + _id(ref)


def _object_array_dump(object_id: int, array_class_id: int, elements: list[int]) -> bytes:
    return (
        _u1(0x22)
        + _id(object_id)
        + _u4(0)
        + _u4(len(elements))
        + _id(array_class_id)
        + b"".join(_id(elem) for elem in elements)
    )


def _root_unknown(object_id: int) -> bytes:
    return _u1(0xFF) + _id(object_id)


def _root_unreachable(object_id: int) -> bytes:
    return _u1(0x8F) + _id(object_id)


def _build_test_hprof(path: Path) -> None:
    header = b"JAVA PROFILE 1.0.2\x00" + _u4(4) + _u8(0)
    records = [
        _string_record(1, "com/example/Node"),
        _string_record(2, "next"),
        _load_class_record(0x100, 1),
    ]
    heap = (
        _root_unknown(0x200)
        + _root_unreachable(0x400)
        + _class_dump(0x100, 2)
        + _instance_dump(0x200, 0x100, 0x300)
        + _instance_dump(0x300, 0x100, 0)
        + _instance_dump(0x400, 0x100, 0)
    )
    records.append(_record(0x0C, heap))
    path.write_bytes(header + b"".join(records))


class MinimalHprofTests(unittest.TestCase):
    def test_parser_and_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hprof = Path(tmp) / "sample.hprof"
            _build_test_hprof(hprof)

            snapshot = HprofParser().parse(hprof)
            result = analyze_snapshot(snapshot, top_n=10)

            self.assertEqual(snapshot.id_size, 4)
            self.assertEqual(result.root_count, 1)
            self.assertEqual(result.reachable_count, 2)
            self.assertEqual(result.non_collectable_size, 8)
            self.assertEqual(result.class_summaries[0].type_name, "com.example.Node")
            self.assertEqual(result.class_summaries[0].shallow_size, 8)

            self.assertTrue(result.top_retainers)
            self.assertEqual(result.top_retainers[0].object_id, 0x200)
            self.assertEqual(result.top_retainers[0].retained_size, 8)

    def test_include_unreachable_root_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hprof = Path(tmp) / "sample.hprof"
            _build_test_hprof(hprof)

            without_flag = HprofParser(include_unreachable_roots=False).parse(hprof)
            with_flag = HprofParser(include_unreachable_roots=True).parse(hprof)

            res_without = analyze_snapshot(without_flag, top_n=10)
            res_with = analyze_snapshot(with_flag, top_n=10)

            self.assertEqual(res_without.reachable_count, 2)
            self.assertEqual(res_with.reachable_count, 3)
            self.assertEqual(res_without.non_collectable_size, 8)
            self.assertEqual(res_with.non_collectable_size, 12)

    def test_object_array_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hprof = Path(tmp) / "array.hprof"
            header = b"JAVA PROFILE 1.0.2\x00" + _u4(4) + _u8(0)
            records = [
                _string_record(1, "com/example/Node"),
                _string_record(2, "next"),
                _string_record(3, "[Lcom/example/Node;"),
                _load_class_record(0x100, 1),
                _load_class_record(0x101, 3),
            ]
            heap = (
                _root_unknown(0x500)
                + _class_dump(0x100, 2)
                + _class_dump_no_fields(0x101)
                + _instance_dump(0x200, 0x100, 0)
                + _instance_dump(0x300, 0x100, 0)
                + _object_array_dump(0x500, 0x101, [0x200, 0x300])
            )
            records.append(_record(0x0C, heap))
            hprof.write_bytes(header + b"".join(records))

            snapshot = HprofParser().parse(hprof)
            result = analyze_snapshot(snapshot, top_n=10)

            self.assertEqual(result.root_count, 1)
            self.assertEqual(result.reachable_count, 3)
            self.assertEqual(result.non_collectable_size, 16)
            self.assertTrue(result.top_retainers)
            self.assertEqual(result.top_retainers[0].object_id, 0x500)
            self.assertEqual(result.top_retainers[0].retained_size, 16)

    def test_dominator_on_converging_graph(self) -> None:
        snapshot = HeapSnapshot(id_size=4, version="test")
        for obj_id in (0xA, 0xB, 0xC, 0xD):
            snapshot.ensure_object(obj_id, kind="instance", class_id=0x100, shallow_size=4)

        snapshot.roots.update((0xA, 0xB))
        snapshot.objects[0xA].refs.append(0xC)
        snapshot.objects[0xB].refs.append(0xC)
        snapshot.objects[0xC].refs.append(0xD)

        result = analyze_snapshot(snapshot, top_n=10)
        self.assertEqual(result.reachable_count, 4)
        self.assertEqual(result.non_collectable_size, 16)

        retained_by_id = {row.object_id: row.retained_size for row in result.top_retainers}
        self.assertEqual(retained_by_id[0xA], 4)
        self.assertEqual(retained_by_id[0xB], 4)
        self.assertEqual(retained_by_id[0xC], 8)
        self.assertEqual(retained_by_id[0xD], 4)


if __name__ == "__main__":
    unittest.main()
