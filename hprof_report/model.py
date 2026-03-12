from __future__ import annotations

from array import array
from dataclasses import dataclass, field


@dataclass(slots=True)
class ClassInfo:
    class_id: int
    super_class_id: int
    instance_size: int
    instance_field_types: list[int]


@dataclass(slots=True)
class ObjectRecord:
    kind: str
    class_id: int | None
    shallow_size: int
    refs: array
    display_type: str | None = None


@dataclass(slots=True)
class HeapSnapshot:
    id_size: int
    version: str
    strings: dict[int, bytes | str] = field(default_factory=dict)
    class_name_ids: dict[int, int] = field(default_factory=dict)
    classes: dict[int, ClassInfo] = field(default_factory=dict)
    objects: dict[int, ObjectRecord] = field(default_factory=dict)
    roots: set[int] = field(default_factory=set)
    create_placeholders: bool = False

    def ensure_object(
        self,
        object_id: int,
        *,
        kind: str = "unknown",
        class_id: int | None = None,
        shallow_size: int = 0,
        display_type: str | None = None,
    ) -> ObjectRecord:
        existing = self.objects.get(object_id)
        if existing is not None:
            if kind != "unknown":
                existing.kind = kind
            if class_id is not None:
                existing.class_id = class_id
            if shallow_size:
                existing.shallow_size = shallow_size
            if display_type is not None:
                existing.display_type = display_type
            return existing

        record = ObjectRecord(
            kind=kind,
            class_id=class_id,
            shallow_size=shallow_size,
            refs=self._new_ref_array(),
            display_type=display_type,
        )
        self.objects[object_id] = record
        return record

    def add_ref(self, source_id: int, target_id: int) -> None:
        if target_id == 0:
            return
        source = self.ensure_object(source_id)
        source.refs.append(target_id)
        if self.create_placeholders:
            self.ensure_object(target_id)

    def get_class_name(self, class_id: int | None) -> str:
        if class_id is None:
            return "<unknown>"
        name_id = self.class_name_ids.get(class_id)
        if name_id is None:
            return f"<class@0x{class_id:x}>"
        raw = self.strings.get(name_id)
        if raw is None:
            return f"<string@0x{name_id:x}>"
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
            self.strings[name_id] = text
        else:
            text = raw
        return pretty_class_name(text)

    def object_type_name(self, obj: ObjectRecord) -> str:
        if obj.display_type:
            return obj.display_type
        if obj.kind == "instance":
            return self.get_class_name(obj.class_id)
        if obj.kind == "object_array":
            return self.get_class_name(obj.class_id)
        if obj.kind == "class":
            return f"{self.get_class_name(obj.class_id)} (class)"
        if obj.kind == "primitive_array":
            return "primitive[]"
        return "<unknown>"

    def _new_ref_array(self) -> array:
        return array("I") if self.id_size == 4 else array("Q")


_PRIMITIVE_DESC = {
    "B": "byte",
    "C": "char",
    "D": "double",
    "F": "float",
    "I": "int",
    "J": "long",
    "S": "short",
    "Z": "boolean",
}


def pretty_class_name(raw: str) -> str:
    # Handles normal class names (java/lang/String) and descriptor arrays ([Ljava/lang/String;).
    dims = 0
    while dims < len(raw) and raw[dims] == "[":
        dims += 1
    if dims:
        comp = raw[dims:]
        if comp.startswith("L") and comp.endswith(";"):
            base = comp[1:-1].replace("/", ".")
        else:
            base = _PRIMITIVE_DESC.get(comp, comp)
        return base + "[]" * dims
    return raw.replace("/", ".")
