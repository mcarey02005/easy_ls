#!/usr/bin/env python3
from __future__ import annotations

import base64
import shutil
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
INPUT_DIR = ROOT_DIR / "input"
OUTPUT_DIR = ROOT_DIR / "src"
SCRIPT_CLASSES = {"Script", "ModuleScript"}
IGNORED_CLASSES = {"LocalScript"}
INVALID_PATH_CHARS = '<>:"/\\|?*'
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


class AttributeDecodeError(ValueError):
    pass


class BinaryReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def _take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise AttributeDecodeError("Unexpected end of attribute data")
        chunk = self.data[self.offset:end]
        self.offset = end
        return chunk

    def read_u8(self) -> int:
        return self._take(1)[0]

    def read_u32(self) -> int:
        return struct.unpack("<I", self._take(4))[0]

    def read_i32(self) -> int:
        return struct.unpack("<i", self._take(4))[0]

    def read_f32(self) -> float:
        return struct.unpack("<f", self._take(4))[0]

    def read_f64(self) -> float:
        return struct.unpack("<d", self._take(8))[0]

    def read_string_bytes(self) -> bytes:
        length = self.read_u32()
        return self._take(length)

    def skip_value(self, value_type: int) -> None:
        if value_type == 0x02:
            self.read_string_bytes()
            return
        if value_type == 0x03:
            self._take(1)
            return
        if value_type == 0x05:
            self._take(4)
            return
        if value_type == 0x06:
            self._take(8)
            return
        if value_type == 0x09:
            self._take(8)
            return
        if value_type == 0x0A:
            self._take(16)
            return
        if value_type == 0x0E:
            self._take(4)
            return
        if value_type == 0x0F:
            self._take(12)
            return
        if value_type == 0x10:
            self._take(8)
            return
        if value_type == 0x11:
            self._take(12)
            return
        if value_type == 0x14:
            self._skip_cframe()
            return
        if value_type == 0x17:
            count = self.read_u32()
            self._take(count * 12)
            return
        if value_type == 0x19:
            count = self.read_u32()
            self._take(count * 20)
            return
        if value_type == 0x1B:
            self._take(8)
            return
        if value_type == 0x1C:
            self._take(16)
            return
        raise AttributeDecodeError(f"Unsupported attribute value type: 0x{value_type:02X}")

    def _skip_cframe(self) -> None:
        self._take(12)
        rotation_id = self.read_u8()
        if rotation_id == 0:
            self._take(36)


def find_single_rbxmx(input_dir: Path) -> Path:
    files = sorted(path for path in input_dir.glob("*.rbxmx") if path.is_file())
    if len(files) != 1:
        raise SystemExit(
            f"Expected exactly one .rbxmx file in {input_dir}, found {len(files)}."
        )
    return files[0]


def clear_output_dir(output_dir: Path) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)


def get_name(item: ET.Element) -> str:
    properties = item.find("Properties")
    if properties is None:
        raise ValueError("Item is missing a Properties node")

    for prop in properties:
        if prop.attrib.get("name") == "Name":
            return prop.text or ""

    raise ValueError("Item is missing its Name property")


def get_property_text(item: ET.Element, property_name: str) -> str | None:
    properties = item.find("Properties")
    if properties is None:
        return None

    for prop in properties:
        if prop.attrib.get("name") == property_name:
            return prop.text or ""

    return None


def sanitize_name(name: str) -> str:
    sanitized = "".join("_" if char in INVALID_PATH_CHARS else char for char in name)
    sanitized = sanitized.rstrip(" .")
    if not sanitized:
        sanitized = "_"
    if sanitized.upper() in WINDOWS_RESERVED_NAMES:
        sanitized = f"{sanitized}_"
    return sanitized


def build_unique_names(children: list[ET.Element]) -> dict[int, str]:
    counters: dict[str, int] = {}
    result: dict[int, str] = {}

    for child in children:
        base_name = sanitize_name(get_name(child))
        next_index = counters.get(base_name, 0) + 1
        counters[base_name] = next_index
        if next_index == 1:
            result[id(child)] = base_name
        else:
            result[id(child)] = f"{base_name}__{next_index}"

    return result


def extract_c_attribute_bytes(item: ET.Element) -> bytes | None:
    encoded = get_property_text(item, "AttributesSerialize")
    if not encoded or not encoded.strip():
        return None

    raw_bytes = base64.b64decode(encoded)
    reader = BinaryReader(raw_bytes)
    entry_count = reader.read_u32()

    for _ in range(entry_count):
        key_bytes = reader.read_string_bytes()
        key = key_bytes.decode("utf-8", errors="strict")
        value_type = reader.read_u8()
        if key == "c":
            if value_type != 0x02:
                raise AttributeDecodeError("The c attribute exists but is not a string value")
            return reader.read_string_bytes()
        reader.skip_value(value_type)

    return None


def export_item(item: ET.Element, parent_dir: Path) -> tuple[int, int]:
    class_name = item.attrib.get("class", "")
    if class_name in IGNORED_CLASSES:
        return 0, 0

    instance_name = get_name(item)
    instance_dir = parent_dir / sanitize_name(instance_name)
    instance_dir.mkdir(parents=True, exist_ok=True)

    directories_created = 1
    text_files_created = 0

    if class_name in SCRIPT_CLASSES:
        c_bytes = extract_c_attribute_bytes(item)
        if c_bytes is not None:
            text_path = instance_dir / f"{sanitize_name(instance_name)}.txt"
            text_path.write_bytes(c_bytes)
            text_files_created += 1

    children = [child for child in item if child.tag == "Item"]
    unique_names = build_unique_names(children)

    for child in children:
        if child.attrib.get("class", "") in IGNORED_CLASSES:
            continue

        child_class = child.attrib.get("class", "")
        child_instance_name = get_name(child)
        child_dir_name = unique_names[id(child)]
        child_dir = instance_dir / child_dir_name

        if child_class in IGNORED_CLASSES:
            continue

        child_directories, child_text_files = export_item_with_prebuilt_dir(
            child,
            child_dir,
            child_instance_name,
        )
        directories_created += child_directories
        text_files_created += child_text_files

    return directories_created, text_files_created


def export_item_with_prebuilt_dir(
    item: ET.Element,
    instance_dir: Path,
    original_name: str,
) -> tuple[int, int]:
    class_name = item.attrib.get("class", "")
    if class_name in IGNORED_CLASSES:
        return 0, 0

    instance_dir.mkdir(parents=True, exist_ok=True)

    directories_created = 1
    text_files_created = 0

    if class_name in SCRIPT_CLASSES:
        c_bytes = extract_c_attribute_bytes(item)
        if c_bytes is not None:
            text_path = instance_dir / f"{sanitize_name(original_name)}.txt"
            text_path.write_bytes(c_bytes)
            text_files_created += 1

    children = [child for child in item if child.tag == "Item"]
    unique_names = build_unique_names(children)

    for child in children:
        if child.attrib.get("class", "") in IGNORED_CLASSES:
            continue

        child_name = get_name(child)
        child_dir = instance_dir / unique_names[id(child)]
        child_directories, child_text_files = export_item_with_prebuilt_dir(
            child,
            child_dir,
            child_name,
        )
        directories_created += child_directories
        text_files_created += child_text_files

    return directories_created, text_files_created


def export_tree(xml_path: Path, output_dir: Path) -> tuple[int, int]:
    root = ET.parse(xml_path).getroot()
    top_level_items = [child for child in root if child.tag == "Item"]
    unique_names = build_unique_names(top_level_items)

    directories_created = 0
    text_files_created = 0

    for item in top_level_items:
        if item.attrib.get("class", "") in IGNORED_CLASSES:
            continue

        item_name = get_name(item)
        item_dir = output_dir / unique_names[id(item)]
        item_directories, item_text_files = export_item_with_prebuilt_dir(
            item,
            item_dir,
            item_name,
        )
        directories_created += item_directories
        text_files_created += item_text_files

    return directories_created, text_files_created


def main() -> int:
    try:
        xml_path = find_single_rbxmx(INPUT_DIR)
        clear_output_dir(OUTPUT_DIR)
        directories_created, text_files_created = export_tree(xml_path, OUTPUT_DIR)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Input: {xml_path.name}")
    print(f"Output: {OUTPUT_DIR}")
    print(f"Directories created: {directories_created}")
    print(f"Text files created: {text_files_created}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())