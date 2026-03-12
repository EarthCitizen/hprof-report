from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import BinaryIO

from .model import ClassInfo, HeapSnapshot


TAG_STRING = 0x01
TAG_LOAD_CLASS = 0x02
TAG_HEAP_DUMP = 0x0C
TAG_HEAP_DUMP_SEGMENT = 0x1C

SUB_ROOT_UNKNOWN = 0xFF
SUB_ROOT_JNI_GLOBAL = 0x01
SUB_ROOT_JNI_LOCAL = 0x02
SUB_ROOT_JAVA_FRAME = 0x03
SUB_ROOT_NATIVE_STACK = 0x04
SUB_ROOT_STICKY_CLASS = 0x05
SUB_ROOT_THREAD_BLOCK = 0x06
SUB_ROOT_MONITOR_USED = 0x07
SUB_ROOT_THREAD_OBJECT = 0x08
SUB_CLASS_DUMP = 0x20
SUB_INSTANCE_DUMP = 0x21
SUB_OBJECT_ARRAY_DUMP = 0x22
SUB_PRIMITIVE_ARRAY_DUMP = 0x23
SUB_ROOT_INTERNED_STRING = 0x89
SUB_ROOT_FINALIZING = 0x8A
SUB_ROOT_DEBUGGER = 0x8B
SUB_ROOT_REFERENCE_CLEANUP = 0x8C
SUB_ROOT_VM_INTERNAL = 0x8D
SUB_ROOT_JNI_MONITOR = 0x8E
SUB_ROOT_UNREACHABLE = 0x8F

TYPE_OBJECT = 2
TYPE_BOOLEAN = 4
TYPE_CHAR = 5
TYPE_FLOAT = 6
TYPE_DOUBLE = 7
TYPE_BYTE = 8
TYPE_SHORT = 9
TYPE_INT = 10
TYPE_LONG = 11

TYPE_SIZES = {
    TYPE_BOOLEAN: 1,
    TYPE_BYTE: 1,
    TYPE_CHAR: 2,
    TYPE_SHORT: 2,
    TYPE_FLOAT: 4,
    TYPE_INT: 4,
    TYPE_DOUBLE: 8,
    TYPE_LONG: 8,
}

PRIMITIVE_ARRAY_NAMES = {
    TYPE_BOOLEAN: "boolean[]",
    TYPE_CHAR: "char[]",
    TYPE_FLOAT: "float[]",
    TYPE_DOUBLE: "double[]",
    TYPE_BYTE: "byte[]",
    TYPE_SHORT: "short[]",
    TYPE_INT: "int[]",
    TYPE_LONG: "long[]",
}


@dataclass(slots=True)
class _PendingInstance:
    object_id: int
    class_id: int
    raw_data: bytes


class HprofParser:
    def __init__(self, *, include_unreachable_roots: bool = False) -> None:
        self.include_unreachable_roots = include_unreachable_roots
        self._pending_instances: list[_PendingInstance] = []
        self._field_type_cache: dict[int, list[int]] = {}

    def parse(self, file_path: str | Path) -> HeapSnapshot:
        path = Path(file_path)
        with path.open("rb") as fp:
            version = self._read_header_version(fp)
            id_size = self._read_u4(fp)
            if id_size not in (4, 8):
                raise ValueError(f"Unsupported HPROF identifier size: {id_size}")
            _ = self._read_u8(fp)  # timestamp

            snapshot = HeapSnapshot(id_size=id_size, version=version)

            while True:
                header = fp.read(9)
                if not header:
                    break
                if len(header) != 9:
                    raise ValueError("Corrupted HPROF: truncated record header")
                tag = header[0]
                # 4-byte microseconds field at header[1:5], not needed for analysis.
                length = struct.unpack(">I", header[5:9])[0]
                self._parse_record(fp, snapshot, tag, length)

        self._resolve_pending_instances(snapshot)
        return snapshot

    def _parse_record(self, fp: BinaryIO, snapshot: HeapSnapshot, tag: int, length: int) -> None:
        if tag == TAG_STRING:
            self._parse_string_record(fp, snapshot, length)
            return
        if tag == TAG_LOAD_CLASS:
            self._parse_load_class_record(fp, snapshot, length)
            return
        if tag in (TAG_HEAP_DUMP, TAG_HEAP_DUMP_SEGMENT):
            self._parse_heap_dump_segment(fp, snapshot, length)
            return
        self._skip_bytes(fp, length)

    def _parse_string_record(self, fp: BinaryIO, snapshot: HeapSnapshot, length: int) -> None:
        string_id = self._read_id(fp, snapshot.id_size)
        text_len = length - snapshot.id_size
        if text_len < 0:
            raise ValueError("Corrupted HPROF: invalid string record length")
        raw = self._read_exact(fp, text_len)
        snapshot.strings[string_id] = raw.decode("utf-8", errors="replace")

    def _parse_load_class_record(self, fp: BinaryIO, snapshot: HeapSnapshot, length: int) -> None:
        if length < 8 + 2 * snapshot.id_size:
            raise ValueError("Corrupted HPROF: invalid LOAD_CLASS record length")
        _ = self._read_u4(fp)  # class serial number
        class_object_id = self._read_id(fp, snapshot.id_size)
        _ = self._read_u4(fp)  # stack trace serial
        class_name_string_id = self._read_id(fp, snapshot.id_size)
        snapshot.class_name_ids[class_object_id] = class_name_string_id
        consumed = 8 + 2 * snapshot.id_size
        if length > consumed:
            self._skip_bytes(fp, length - consumed)

    def _parse_heap_dump_segment(self, fp: BinaryIO, snapshot: HeapSnapshot, length: int) -> None:
        end_pos = fp.tell() + length
        while fp.tell() < end_pos:
            subtag = self._read_u1(fp)
            if subtag in (
                SUB_ROOT_UNKNOWN,
                SUB_ROOT_STICKY_CLASS,
                SUB_ROOT_MONITOR_USED,
                SUB_ROOT_INTERNED_STRING,
                SUB_ROOT_FINALIZING,
                SUB_ROOT_DEBUGGER,
                SUB_ROOT_REFERENCE_CLEANUP,
                SUB_ROOT_VM_INTERNAL,
            ):
                self._add_root(snapshot, self._read_id(fp, snapshot.id_size))
                continue

            if subtag == SUB_ROOT_UNREACHABLE:
                root_id = self._read_id(fp, snapshot.id_size)
                if self.include_unreachable_roots:
                    self._add_root(snapshot, root_id)
                continue

            if subtag == SUB_ROOT_JNI_GLOBAL:
                self._add_root(snapshot, self._read_id(fp, snapshot.id_size))
                _ = self._read_id(fp, snapshot.id_size)
                continue
            if subtag in (SUB_ROOT_JNI_LOCAL, SUB_ROOT_JAVA_FRAME):
                self._add_root(snapshot, self._read_id(fp, snapshot.id_size))
                _ = self._read_u4(fp)
                _ = self._read_u4(fp)
                continue
            if subtag in (SUB_ROOT_NATIVE_STACK, SUB_ROOT_THREAD_BLOCK):
                self._add_root(snapshot, self._read_id(fp, snapshot.id_size))
                _ = self._read_u4(fp)
                continue
            if subtag in (SUB_ROOT_THREAD_OBJECT, SUB_ROOT_JNI_MONITOR):
                self._add_root(snapshot, self._read_id(fp, snapshot.id_size))
                _ = self._read_u4(fp)
                _ = self._read_u4(fp)
                continue

            if subtag == SUB_CLASS_DUMP:
                self._parse_class_dump(fp, snapshot)
                continue
            if subtag == SUB_INSTANCE_DUMP:
                self._parse_instance_dump(fp, snapshot)
                continue
            if subtag == SUB_OBJECT_ARRAY_DUMP:
                self._parse_object_array_dump(fp, snapshot)
                continue
            if subtag == SUB_PRIMITIVE_ARRAY_DUMP:
                self._parse_primitive_array_dump(fp, snapshot)
                continue

            raise ValueError(f"Unsupported HEAP_DUMP sub-record tag: 0x{subtag:02x}")

        if fp.tell() != end_pos:
            raise ValueError("Corrupted HPROF: heap dump segment overrun/underrun")

    def _parse_class_dump(self, fp: BinaryIO, snapshot: HeapSnapshot) -> None:
        class_id = self._read_id(fp, snapshot.id_size)
        _ = self._read_u4(fp)  # stack trace serial
        super_class_id = self._read_id(fp, snapshot.id_size)
        class_loader_id = self._read_id(fp, snapshot.id_size)
        signers_id = self._read_id(fp, snapshot.id_size)
        protection_domain_id = self._read_id(fp, snapshot.id_size)
        _ = self._read_id(fp, snapshot.id_size)  # reserved
        _ = self._read_id(fp, snapshot.id_size)  # reserved
        instance_size = self._read_u4(fp)

        cp_entries = self._read_u2(fp)
        for _ in range(cp_entries):
            _ = self._read_u2(fp)
            value_type = self._read_u1(fp)
            self._read_typed_value(fp, snapshot.id_size, value_type)

        static_fields = self._read_u2(fp)
        static_ref_values: list[int] = []
        for _ in range(static_fields):
            _ = self._read_id(fp, snapshot.id_size)  # field name string ID
            value_type = self._read_u1(fp)
            value = self._read_typed_value(fp, snapshot.id_size, value_type)
            if value_type == TYPE_OBJECT and isinstance(value, int) and value != 0:
                static_ref_values.append(value)

        instance_fields = self._read_u2(fp)
        instance_field_types: list[int] = []
        for _ in range(instance_fields):
            _ = self._read_id(fp, snapshot.id_size)  # field name string ID
            instance_field_types.append(self._read_u1(fp))

        snapshot.classes[class_id] = ClassInfo(
            class_id=class_id,
            super_class_id=super_class_id,
            instance_size=instance_size,
            instance_field_types=instance_field_types,
        )
        self._field_type_cache.clear()

        class_obj = snapshot.ensure_object(class_id, kind="class", class_id=class_id, shallow_size=0)
        for ref in (super_class_id, class_loader_id, signers_id, protection_domain_id):
            if ref != 0:
                snapshot.add_ref(class_obj.object_id, ref)
        for ref in static_ref_values:
            snapshot.add_ref(class_obj.object_id, ref)

    def _parse_instance_dump(self, fp: BinaryIO, snapshot: HeapSnapshot) -> None:
        object_id = self._read_id(fp, snapshot.id_size)
        _ = self._read_u4(fp)  # stack trace serial
        class_id = self._read_id(fp, snapshot.id_size)
        data_len = self._read_u4(fp)
        raw_data = self._read_exact(fp, data_len)

        obj = snapshot.ensure_object(object_id, kind="instance", class_id=class_id, shallow_size=data_len)
        obj.class_id = class_id
        obj.kind = "instance"
        obj.shallow_size = data_len

        field_types = self._get_instance_field_types(snapshot, class_id)
        if field_types:
            for ref in self._extract_instance_refs(raw_data, field_types, snapshot.id_size):
                snapshot.add_ref(object_id, ref)
        else:
            self._pending_instances.append(_PendingInstance(object_id=object_id, class_id=class_id, raw_data=raw_data))

    def _parse_object_array_dump(self, fp: BinaryIO, snapshot: HeapSnapshot) -> None:
        object_id = self._read_id(fp, snapshot.id_size)
        _ = self._read_u4(fp)  # stack trace serial
        length = self._read_u4(fp)
        array_class_id = self._read_id(fp, snapshot.id_size)

        obj = snapshot.ensure_object(
            object_id,
            kind="object_array",
            class_id=array_class_id,
            shallow_size=length * snapshot.id_size,
        )
        obj.kind = "object_array"
        obj.class_id = array_class_id
        obj.shallow_size = length * snapshot.id_size

        for _ in range(length):
            element_id = self._read_id(fp, snapshot.id_size)
            if element_id != 0:
                snapshot.add_ref(object_id, element_id)

    def _parse_primitive_array_dump(self, fp: BinaryIO, snapshot: HeapSnapshot) -> None:
        object_id = self._read_id(fp, snapshot.id_size)
        _ = self._read_u4(fp)  # stack trace serial
        length = self._read_u4(fp)
        primitive_type = self._read_u1(fp)
        elem_size = TYPE_SIZES.get(primitive_type)
        if elem_size is None:
            raise ValueError(f"Unsupported primitive array element type tag: {primitive_type}")
        payload_size = length * elem_size
        self._skip_bytes(fp, payload_size)

        display_type = PRIMITIVE_ARRAY_NAMES.get(primitive_type, f"<primitive:{primitive_type}>[]")
        obj = snapshot.ensure_object(
            object_id,
            kind="primitive_array",
            class_id=None,
            shallow_size=payload_size,
            display_type=display_type,
        )
        obj.kind = "primitive_array"
        obj.shallow_size = payload_size
        obj.display_type = display_type

    def _resolve_pending_instances(self, snapshot: HeapSnapshot) -> None:
        if not self._pending_instances:
            return
        unresolved: list[_PendingInstance] = []
        for pending in self._pending_instances:
            field_types = self._get_instance_field_types(snapshot, pending.class_id)
            if not field_types:
                unresolved.append(pending)
                continue
            for ref in self._extract_instance_refs(pending.raw_data, field_types, snapshot.id_size):
                snapshot.add_ref(pending.object_id, ref)
        self._pending_instances = unresolved

    def _get_instance_field_types(self, snapshot: HeapSnapshot, class_id: int) -> list[int]:
        cached = self._field_type_cache.get(class_id)
        if cached is not None:
            return cached

        chain_types: list[int] = []
        visited: set[int] = set()
        current = class_id
        while current and current not in visited:
            visited.add(current)
            class_info = snapshot.classes.get(current)
            if class_info is None:
                break
            # HotSpot HPROF format writes fields for the class, then its superclass chain.
            chain_types.extend(class_info.instance_field_types)
            current = class_info.super_class_id

        self._field_type_cache[class_id] = chain_types
        return chain_types

    @staticmethod
    def _extract_instance_refs(raw_data: bytes, field_types: list[int], id_size: int) -> list[int]:
        refs: list[int] = []
        offset = 0
        total = len(raw_data)
        for field_type in field_types:
            size = id_size if field_type == TYPE_OBJECT else TYPE_SIZES.get(field_type)
            if size is None:
                break
            if offset + size > total:
                break
            if field_type == TYPE_OBJECT:
                ref_id = int.from_bytes(raw_data[offset : offset + id_size], "big", signed=False)
                if ref_id != 0:
                    refs.append(ref_id)
            offset += size
            if offset == total:
                break
        return refs

    @staticmethod
    def _add_root(snapshot: HeapSnapshot, object_id: int) -> None:
        if object_id == 0:
            return
        snapshot.roots.add(object_id)
        snapshot.ensure_object(object_id)

    @staticmethod
    def _read_header_version(fp: BinaryIO) -> str:
        buf = bytearray()
        while True:
            one = fp.read(1)
            if not one:
                raise ValueError("Corrupted HPROF: missing header terminator")
            if one == b"\x00":
                break
            buf.extend(one)
        return buf.decode("ascii", errors="replace")

    @staticmethod
    def _read_exact(fp: BinaryIO, size: int) -> bytes:
        if size < 0:
            raise ValueError("Negative read size")
        data = fp.read(size)
        if len(data) != size:
            raise ValueError("Corrupted HPROF: unexpected EOF")
        return data

    @classmethod
    def _read_u1(cls, fp: BinaryIO) -> int:
        return cls._read_exact(fp, 1)[0]

    @classmethod
    def _read_u2(cls, fp: BinaryIO) -> int:
        return struct.unpack(">H", cls._read_exact(fp, 2))[0]

    @classmethod
    def _read_u4(cls, fp: BinaryIO) -> int:
        return struct.unpack(">I", cls._read_exact(fp, 4))[0]

    @classmethod
    def _read_u8(cls, fp: BinaryIO) -> int:
        return struct.unpack(">Q", cls._read_exact(fp, 8))[0]

    @classmethod
    def _read_id(cls, fp: BinaryIO, id_size: int) -> int:
        raw = cls._read_exact(fp, id_size)
        return int.from_bytes(raw, "big", signed=False)

    @classmethod
    def _skip_bytes(cls, fp: BinaryIO, size: int) -> None:
        if size <= 0:
            return
        if hasattr(fp, "seek"):
            fp.seek(size, 1)
            return
        remaining = size
        while remaining:
            chunk = min(remaining, 1024 * 1024)
            _ = cls._read_exact(fp, chunk)
            remaining -= chunk

    @classmethod
    def _read_typed_value(cls, fp: BinaryIO, id_size: int, value_type: int) -> int | float:
        if value_type == TYPE_OBJECT:
            return cls._read_id(fp, id_size)
        if value_type in (TYPE_BOOLEAN, TYPE_BYTE):
            return cls._read_u1(fp)
        if value_type in (TYPE_CHAR, TYPE_SHORT):
            return cls._read_u2(fp)
        if value_type in (TYPE_FLOAT, TYPE_INT):
            return cls._read_u4(fp)
        if value_type in (TYPE_DOUBLE, TYPE_LONG):
            return cls._read_u8(fp)
        raise ValueError(f"Unsupported value type tag: {value_type}")

