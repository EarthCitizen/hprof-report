from __future__ import annotations

from dataclasses import dataclass
import mmap
from pathlib import Path
import struct
import time
from typing import BinaryIO, Callable

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


ProgressCallback = Callable[[str], None]


class HprofParser:
    def __init__(
        self,
        *,
        include_unreachable_roots: bool = False,
        progress: ProgressCallback | None = None,
        progress_interval_seconds: float = 2.0,
        progress_interval_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self.include_unreachable_roots = include_unreachable_roots
        self.progress = progress
        self.progress_interval_seconds = max(0.1, progress_interval_seconds)
        self.progress_interval_bytes = max(1024 * 1024, progress_interval_bytes)

        self._pending_instances: list[_PendingInstance] = []
        self._field_type_cache: dict[int, list[int] | None] = {}
        self._instance_ref_offsets_cache: dict[int, tuple[int, ...] | None] = {}
        self._progress_last_time = 0.0
        self._progress_next_byte_mark = 0
        self._progress_start_time = 0.0
        self._records_parsed = 0
        self._heap_subrecords = 0
        self._strings_parsed = 0
        self._load_classes_parsed = 0
        self._class_dumps_parsed = 0
        self._instance_dumps_parsed = 0
        self._object_arrays_parsed = 0
        self._primitive_arrays_parsed = 0

    def parse(self, file_path: str | Path) -> HeapSnapshot:
        path = Path(file_path)
        file_size = path.stat().st_size
        self._pending_instances = []
        self._field_type_cache.clear()
        self._instance_ref_offsets_cache.clear()
        self._records_parsed = 0
        self._heap_subrecords = 0
        self._strings_parsed = 0
        self._load_classes_parsed = 0
        self._class_dumps_parsed = 0
        self._instance_dumps_parsed = 0
        self._object_arrays_parsed = 0
        self._primitive_arrays_parsed = 0

        self._progress_start_time = time.perf_counter()
        self._progress_last_time = self._progress_start_time
        self._progress_next_byte_mark = self.progress_interval_bytes
        if self.progress is not None:
            self.progress(f"Parser: reading {path} ({_format_bytes(file_size)})")

        with path.open("rb") as base_fp:
            mapped: mmap.mmap | None = None
            fp: BinaryIO = base_fp
            if file_size > 0:
                mapped = mmap.mmap(base_fp.fileno(), length=0, access=mmap.ACCESS_READ)
                fp = mapped
                if self.progress is not None:
                    self.progress("Parser: using memory-mapped input")
            try:
                version = self._read_header_version(fp)
                id_size = self._read_u4(fp)
                if id_size not in (4, 8):
                    raise ValueError(f"Unsupported HPROF identifier size: {id_size}")
                _ = self._read_u8(fp)  # timestamp

                snapshot = HeapSnapshot(id_size=id_size, version=version, create_placeholders=False)
                if self.progress is not None:
                    self.progress(f"Parser: header version={version} id_size={id_size}")

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
                    self._records_parsed += 1
                    self._maybe_report_parse_progress(current_pos=fp.tell(), total_size=file_size, snapshot=snapshot)
            finally:
                if mapped is not None:
                    mapped.close()

        self._resolve_pending_instances(snapshot)
        self._compact_string_table(snapshot)
        self._maybe_report_parse_progress(current_pos=file_size, total_size=file_size, snapshot=snapshot, force=True)
        if self.progress is not None:
            elapsed = time.perf_counter() - self._progress_start_time
            self.progress(
                "Parser: complete "
                f"in {elapsed:.2f}s "
                f"(records={self._records_parsed:,}, heap_subrecords={self._heap_subrecords:,}, "
                f"classes={self._class_dumps_parsed:,}, instances={self._instance_dumps_parsed:,}, "
                f"object_arrays={self._object_arrays_parsed:,}, primitive_arrays={self._primitive_arrays_parsed:,})"
            )
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
        self._strings_parsed += 1
        string_id = self._read_id(fp, snapshot.id_size)
        text_len = length - snapshot.id_size
        if text_len < 0:
            raise ValueError("Corrupted HPROF: invalid string record length")
        snapshot.strings[string_id] = self._read_exact(fp, text_len)

    def _parse_load_class_record(self, fp: BinaryIO, snapshot: HeapSnapshot, length: int) -> None:
        self._load_classes_parsed += 1
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
        remaining = length
        id_size = snapshot.id_size
        while remaining > 0:
            self._heap_subrecords += 1
            subtag = self._read_u1(fp)
            remaining -= 1
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
                self._add_root(snapshot, self._read_id(fp, id_size))
                remaining -= id_size
                continue

            if subtag == SUB_ROOT_UNREACHABLE:
                root_id = self._read_id(fp, id_size)
                if self.include_unreachable_roots:
                    self._add_root(snapshot, root_id)
                remaining -= id_size
                continue

            if subtag == SUB_ROOT_JNI_GLOBAL:
                self._add_root(snapshot, self._read_id(fp, id_size))
                _ = self._read_id(fp, id_size)
                remaining -= id_size * 2
                continue
            if subtag in (SUB_ROOT_JNI_LOCAL, SUB_ROOT_JAVA_FRAME):
                self._add_root(snapshot, self._read_id(fp, id_size))
                _ = self._read_u4(fp)
                _ = self._read_u4(fp)
                remaining -= id_size + 8
                continue
            if subtag in (SUB_ROOT_NATIVE_STACK, SUB_ROOT_THREAD_BLOCK):
                self._add_root(snapshot, self._read_id(fp, id_size))
                _ = self._read_u4(fp)
                remaining -= id_size + 4
                continue
            if subtag in (SUB_ROOT_THREAD_OBJECT, SUB_ROOT_JNI_MONITOR):
                self._add_root(snapshot, self._read_id(fp, id_size))
                _ = self._read_u4(fp)
                _ = self._read_u4(fp)
                remaining -= id_size + 8
                continue

            if subtag == SUB_CLASS_DUMP:
                remaining -= self._parse_class_dump(fp, snapshot)
                continue
            if subtag == SUB_INSTANCE_DUMP:
                remaining -= self._parse_instance_dump(fp, snapshot)
                continue
            if subtag == SUB_OBJECT_ARRAY_DUMP:
                remaining -= self._parse_object_array_dump(fp, snapshot)
                continue
            if subtag == SUB_PRIMITIVE_ARRAY_DUMP:
                remaining -= self._parse_primitive_array_dump(fp, snapshot)
                continue

            raise ValueError(f"Unsupported HEAP_DUMP sub-record tag: 0x{subtag:02x}")

        if remaining != 0:
            raise ValueError("Corrupted HPROF: heap dump segment overrun/underrun")

    def _parse_class_dump(self, fp: BinaryIO, snapshot: HeapSnapshot) -> int:
        self._class_dumps_parsed += 1
        consumed = 0
        class_id = self._read_id(fp, snapshot.id_size)
        consumed += snapshot.id_size
        _ = self._read_u4(fp)  # stack trace serial
        consumed += 4
        super_class_id = self._read_id(fp, snapshot.id_size)
        class_loader_id = self._read_id(fp, snapshot.id_size)
        signers_id = self._read_id(fp, snapshot.id_size)
        protection_domain_id = self._read_id(fp, snapshot.id_size)
        _ = self._read_id(fp, snapshot.id_size)  # reserved
        _ = self._read_id(fp, snapshot.id_size)  # reserved
        consumed += snapshot.id_size * 6
        instance_size = self._read_u4(fp)
        consumed += 4

        cp_entries = self._read_u2(fp)
        consumed += 2
        for _ in range(cp_entries):
            _ = self._read_u2(fp)
            consumed += 2
            value_type = self._read_u1(fp)
            consumed += 1
            value_size = self._size_of_typed_value(snapshot.id_size, value_type)
            consumed += value_size
            self._skip_bytes(fp, value_size)

        static_fields = self._read_u2(fp)
        consumed += 2
        static_ref_values: list[int] = []
        for _ in range(static_fields):
            _ = self._read_id(fp, snapshot.id_size)  # field name string ID
            consumed += snapshot.id_size
            value_type = self._read_u1(fp)
            consumed += 1
            value_size = self._size_of_typed_value(snapshot.id_size, value_type)
            consumed += value_size
            if value_type == TYPE_OBJECT:
                value = self._read_id(fp, snapshot.id_size)
                if value != 0:
                    static_ref_values.append(value)
            else:
                self._skip_bytes(fp, value_size)

        instance_fields = self._read_u2(fp)
        consumed += 2
        instance_field_types: list[int] = []
        for _ in range(instance_fields):
            _ = self._read_id(fp, snapshot.id_size)  # field name string ID
            consumed += snapshot.id_size
            instance_field_types.append(self._read_u1(fp))
            consumed += 1

        snapshot.classes[class_id] = ClassInfo(
            class_id=class_id,
            super_class_id=super_class_id,
            instance_size=instance_size,
            instance_field_types=instance_field_types,
        )
        self._field_type_cache.clear()
        self._instance_ref_offsets_cache.clear()

        class_obj = snapshot.ensure_object(class_id, kind="class", class_id=class_id, shallow_size=0)
        add_ref = class_obj.refs.append
        for ref in (super_class_id, class_loader_id, signers_id, protection_domain_id):
            if ref != 0:
                add_ref(ref)
        for ref in static_ref_values:
            add_ref(ref)
        return consumed

    def _parse_instance_dump(self, fp: BinaryIO, snapshot: HeapSnapshot) -> int:
        self._instance_dumps_parsed += 1
        object_id = self._read_id(fp, snapshot.id_size)
        _ = self._read_u4(fp)  # stack trace serial
        class_id = self._read_id(fp, snapshot.id_size)
        data_len = self._read_u4(fp)

        obj = snapshot.ensure_object(object_id, kind="instance", class_id=class_id, shallow_size=data_len)
        obj.class_id = class_id
        obj.kind = "instance"
        obj.shallow_size = data_len

        ref_offsets = self._get_instance_ref_offsets(snapshot, class_id)
        if ref_offsets is None:
            raw_data = self._read_exact(fp, data_len)
            self._pending_instances.append(_PendingInstance(object_id=object_id, class_id=class_id, raw_data=raw_data))
        elif not ref_offsets:
            self._skip_bytes(fp, data_len)
        else:
            raw_data = self._read_exact(fp, data_len)
            self._append_instance_refs(obj, raw_data, ref_offsets, snapshot.id_size)
        return snapshot.id_size * 2 + 8 + data_len

    def _parse_object_array_dump(self, fp: BinaryIO, snapshot: HeapSnapshot) -> int:
        self._object_arrays_parsed += 1
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

        if length:
            data = self._read_exact(fp, length * snapshot.id_size)
            add_ref = obj.refs.append
            if snapshot.id_size == 4:
                for (element_id,) in struct.iter_unpack(">I", data):
                    if element_id != 0:
                        add_ref(element_id)
            else:
                for (element_id,) in struct.iter_unpack(">Q", data):
                    if element_id != 0:
                        add_ref(element_id)
        return snapshot.id_size * 2 + 8 + (length * snapshot.id_size)

    def _parse_primitive_array_dump(self, fp: BinaryIO, snapshot: HeapSnapshot) -> int:
        self._primitive_arrays_parsed += 1
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
        return snapshot.id_size + 9 + payload_size

    def _resolve_pending_instances(self, snapshot: HeapSnapshot) -> None:
        if not self._pending_instances:
            return
        if self.progress is not None:
            self.progress(f"Parser: resolving {len(self._pending_instances):,} deferred instances")
        unresolved: list[_PendingInstance] = []
        for pending in self._pending_instances:
            ref_offsets = self._get_instance_ref_offsets(snapshot, pending.class_id)
            if ref_offsets is None:
                unresolved.append(pending)
                continue
            obj = snapshot.objects.get(pending.object_id)
            if obj is None:
                continue
            self._append_instance_refs(obj, pending.raw_data, ref_offsets, snapshot.id_size)
        self._pending_instances = unresolved
        if unresolved and self.progress is not None:
            self.progress(
                f"Parser: warning {len(unresolved):,} instances still unresolved due to missing class metadata"
            )

    def _compact_string_table(self, snapshot: HeapSnapshot) -> None:
        if not snapshot.strings:
            return
        needed_ids = set(snapshot.class_name_ids.values())
        if not needed_ids:
            removed = len(snapshot.strings)
            snapshot.strings = {}
            if removed and self.progress is not None:
                self.progress(f"Parser: dropped {removed:,} unused strings")
            return
        if len(needed_ids) >= len(snapshot.strings):
            return
        compacted = {sid: snapshot.strings[sid] for sid in needed_ids if sid in snapshot.strings}
        removed = len(snapshot.strings) - len(compacted)
        snapshot.strings = compacted
        if removed and self.progress is not None:
            self.progress(f"Parser: dropped {removed:,} unused strings")

    def _get_instance_field_types(self, snapshot: HeapSnapshot, class_id: int) -> list[int]:
        if class_id in self._field_type_cache:
            cached = self._field_type_cache[class_id]
            return cached if cached is not None else []

        chain_types: list[int] = []
        visited: set[int] = set()
        current = class_id
        while current and current not in visited:
            visited.add(current)
            class_info = snapshot.classes.get(current)
            if class_info is None:
                self._field_type_cache[class_id] = None
                return []
            # HotSpot HPROF format writes fields for the class, then its superclass chain.
            chain_types.extend(class_info.instance_field_types)
            current = class_info.super_class_id

        self._field_type_cache[class_id] = chain_types
        return chain_types

    def _get_instance_ref_offsets(self, snapshot: HeapSnapshot, class_id: int) -> tuple[int, ...] | None:
        if class_id in self._instance_ref_offsets_cache:
            return self._instance_ref_offsets_cache[class_id]
        field_types = self._get_instance_field_types(snapshot, class_id)
        if not field_types:
            if class_id not in snapshot.classes:
                self._instance_ref_offsets_cache[class_id] = None
                return None
            self._instance_ref_offsets_cache[class_id] = ()
            return ()

        offsets: list[int] = []
        offset = 0
        for field_type in field_types:
            if field_type == TYPE_OBJECT:
                offsets.append(offset)
                offset += snapshot.id_size
                continue
            field_size = TYPE_SIZES.get(field_type)
            if field_size is None:
                break
            offset += field_size
        result = tuple(offsets)
        self._instance_ref_offsets_cache[class_id] = result
        return result

    @staticmethod
    def _append_instance_refs(obj, raw_data: bytes, ref_offsets: tuple[int, ...], id_size: int) -> None:
        if not ref_offsets:
            return
        data_size = len(raw_data)
        add_ref = obj.refs.append
        if id_size == 4:
            unpack_from = struct.unpack_from
            for offset in ref_offsets:
                if offset + 4 > data_size:
                    break
                ref_id = unpack_from(">I", raw_data, offset)[0]
                if ref_id != 0:
                    add_ref(ref_id)
            return
        unpack_from = struct.unpack_from
        for offset in ref_offsets:
            if offset + 8 > data_size:
                break
            ref_id = unpack_from(">Q", raw_data, offset)[0]
            if ref_id != 0:
                add_ref(ref_id)

    @staticmethod
    def _add_root(snapshot: HeapSnapshot, object_id: int) -> None:
        if object_id == 0:
            return
        snapshot.roots.add(object_id)

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

    @staticmethod
    def _size_of_typed_value(id_size: int, value_type: int) -> int:
        if value_type == TYPE_OBJECT:
            return id_size
        size = TYPE_SIZES.get(value_type)
        if size is None:
            raise ValueError(f"Unsupported value type tag: {value_type}")
        return size

    def _maybe_report_parse_progress(
        self,
        *,
        current_pos: int,
        total_size: int,
        snapshot: HeapSnapshot,
        force: bool = False,
    ) -> None:
        if self.progress is None:
            return

        now = time.perf_counter()
        time_due = (now - self._progress_last_time) >= self.progress_interval_seconds
        byte_due = current_pos >= self._progress_next_byte_mark
        if not (force or time_due or byte_due):
            return

        if byte_due:
            while self._progress_next_byte_mark <= current_pos:
                self._progress_next_byte_mark += self.progress_interval_bytes

        elapsed = now - self._progress_start_time
        pct = (current_pos * 100.0 / total_size) if total_size else 0.0
        self.progress(
            "Parser: "
            f"{pct:5.1f}% ({_format_bytes(current_pos)}/{_format_bytes(total_size)}) "
            f"elapsed={elapsed:.1f}s records={self._records_parsed:,} "
            f"objects={len(snapshot.objects):,} roots={len(snapshot.roots):,}"
        )
        self._progress_last_time = now


def _format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    units = ("KiB", "MiB", "GiB", "TiB")
    size = float(value)
    for unit in units:
        size /= 1024.0
        if size < 1024.0:
            return f"{size:.2f} {unit}"
    return f"{size:.2f} PiB"
