# (C) 2025 Noverse. All Rights Reserved.
# https://github.com/nohuto
# https://discord.gg/E2ybG4j9jU

import argparse, io, json, logging, re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Match, Optional, Sequence, Tuple, cast
try:
    import yaml
except ImportError:
    yaml = None
from xml.etree import ElementTree as et

LOG = logging.getLogger("admx_parser")
STRING_TOKEN = re.compile(r"\$\((?:string|String)\.(?P<id>[^)]+)\)")
UNICODE_ENCODING_PATTERN = re.compile(br"encoding\s*=\s*(?P<quote>['\"])unicode(?P=quote)", re.IGNORECASE)
UNICODE_ENCODING_TEXT_PATTERN = re.compile(r"encoding\s*=\s*(?P<quote>['\"])unicode(?P=quote)", re.IGNORECASE)
INLINE_ELEMENTS_PATTERN = re.compile(
    r'(?P<indent>[ \t]*)"Elements": "(?P<marker>__INLINE_ELEMENTS_\d+__)"(?P<trailing>,?)'
)

def _load_xml_tree(path: Path) -> "et.ElementTree[Any]":
    try:
        return et.parse(path)
    except LookupError:
        raw = path.read_bytes()
        fixed = _normalize_unicode_encoding(raw)
        if fixed is not None:
            return et.parse(io.BytesIO(fixed))
        raise

def _normalize_unicode_encoding(raw: bytes) -> Optional[bytes]:
    if UNICODE_ENCODING_PATTERN.search(raw):
        def repl(match: Match[bytes]) -> bytes:
            quote = match.group("quote")
            return b"encoding=" + quote + b"utf-16" + quote

        return UNICODE_ENCODING_PATTERN.sub(repl, raw, count=1)

    for encoding in ("utf-16", "utf-16-le", "utf-16-be"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if UNICODE_ENCODING_TEXT_PATTERN.search(text):
            def repl_text(match: re.Match[str]) -> str:
                quote = match.group("quote")
                return f"encoding={quote}utf-16{quote}"

            text = UNICODE_ENCODING_TEXT_PATTERN.sub(repl_text, text, count=1)
            return text.encode(encoding)
    return None


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse Windows ADMX/ADML policy definitions into structured data.",
    )
    parser.add_argument(
        "-d",
        "--definitions",
        type=Path,
        default=Path(r"C:\Windows\PolicyDefinitions"),
        help="Path to the PolicyDefinitions directory. Defaults to C:\\Windows\\PolicyDefinitions.",
    )
    parser.add_argument(
        "-l",
        "--language",
        dest="languages",
        action="append",
        help="Language folder to include (can be added multiple times). Defaults to auto discovery.",
    )
    parser.add_argument(
        "-i",
        "--ignore",
        dest="ignored_admx",
        action="append",
        help="ADMX base name to ignore (without extension).",
    )
    parser.add_argument(
        "--class",
        dest="class_filter",
        choices=("Machine", "User"),
        action="append",
        help="Limit output to the supplied policy class. Can be specified multiple times.",
    )
    parser.add_argument(
        "--category",
        dest="category_filter",
        help="Filter policies whose category contains this string (case insensitive).",
    )
    parser.add_argument(
        "--policy",
        dest="policy_filter",
        help="Filter policies whose internal or display name contains this string (case insensitive).",
    )
    parser.add_argument(
        "--include-obsolete",
        action="store_true",
        help="Include policies marked as deprecated/obsolete/unsupported.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "yaml"),
        default="json",
        help="Output format selection for stdout and file output.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to save the serialized payload.",
    )
    parser.add_argument(
        "--compress",
        action="store_true",
        help="Emit minified JSON output (ignored when --format yaml).",
    )
    return parser

class AdmxParser:
    def __init__(
        self,
        *,
        definitions_path: Path,
        languages: Optional[Sequence[str]] = None,
        ignored_admx: Optional[Sequence[str]] = None,
        include_obsolete: bool = False,
        class_filter: Optional[Sequence[str]] = None,
        category_filter: Optional[str] = None,
        policy_filter: Optional[str] = None,
    ) -> None:
        self.definitions_path = definitions_path.expanduser().resolve()
        if not self.definitions_path.exists():
            raise FileNotFoundError(f"Definitions path '{self.definitions_path}' was not found.")
        self.include_obsolete = include_obsolete
        self.ignore_set = {item.lower().rstrip(".admx") for item in (ignored_admx or [])}
        self.languages = self._compute_languages(languages)
        self._language_dirs = [p for p in self.definitions_path.iterdir() if p.is_dir()]
        self._string_cache: Dict[tuple[str, str], Dict[str, str]] = {}
        self._supported_text_cache: Dict[str, str] = {}
        self._supported_index_built = False
        self.class_filter = {c.lower() for c in (class_filter or [])}
        self.category_filter = category_filter.lower() if category_filter else None
        self.policy_filter = policy_filter.lower() if policy_filter else None

    def parse(self) -> List[Dict[str, object]]:
        self._ensure_supported_index()
        records: List[Dict[str, object]] = []
        for admx_path in sorted(self.definitions_path.glob("*.admx")):
            base_name = admx_path.stem
            if base_name.lower() in self.ignore_set:
                LOG.debug(f"Skipping ignored ADMX: {admx_path.name}")
                continue
            file_records = list(self._parse_admx(admx_path))
            LOG.info(f"{admx_path.name}: {len(file_records)} policies")
            records.extend(file_records)
        return records

    def _ensure_supported_index(self) -> None:
        if self._supported_index_built:
            return
        for admx_path in sorted(self.definitions_path.glob("*.admx")):
            if not admx_path.is_file():
                continue
            try:
                tree = _load_xml_tree(admx_path)
            except et.ParseError as exc:
                LOG.warning(f"Unable to index supported definitions in {admx_path.name}: {exc}")
                continue
            except LookupError as exc:
                LOG.warning(f"Unsupported encoding in {admx_path.name}: {exc}")
                continue
            root = cast(et.Element, tree.getroot())
            namespace = self._extract_namespace(root)
            q = lambda tag: f"{{{namespace}}}{tag}" if namespace else tag
            self._collect_supported_definitions(root, q, admx_path.stem)
        self._supported_index_built = True

    def _parse_admx(self, admx_path: Path) -> Iterable[Dict[str, object]]:
        try:
            tree = _load_xml_tree(admx_path)
        except et.ParseError as exc:
            LOG.warning(f"Unable to parse {admx_path.name}: {exc}")
            return []
        except LookupError as exc:
            LOG.warning(f"Unsupported encoding in {admx_path.name}: {exc}")
            return []

        root = cast(et.Element, tree.getroot())
        namespace = self._extract_namespace(root)
        q = lambda tag: f"{{{namespace}}}{tag}" if namespace else tag

        policy_namespaces = root.find(q("policyNamespaces"))
        target_namespace = ""
        if policy_namespaces is not None:
            target_node = policy_namespaces.find(q("target"))
            if target_node is not None:
                target_namespace = target_node.get("namespace", "")

        policies_node = root.find(q("policies"))
        if policies_node is None:
            return []

        for policy in policies_node.findall(q("policy")):
            policy_name = policy.get("name", "")
            policy_class = policy.get("class", "")
            if self.class_filter and policy_class.lower() not in self.class_filter:
                continue

            display_name = self._resolve_string(policy.get("displayName", ""), admx_path.stem)
            explain_text = self._clean_text(self._resolve_string(policy.get("explainText", ""), admx_path.stem))
            supported = self._extract_supported(policy, q, admx_path.stem)
            if not self.include_obsolete and self._looks_obsolete(explain_text, supported):
                continue

            category_name = ""
            parent_category = policy.find(q("parentCategory"))
            if parent_category is not None:
                category_name = self._strip_prefix(parent_category.get("ref", ""))

            if self.category_filter and self.category_filter not in category_name.lower():
                continue

            if self.policy_filter:
                combined = f"{policy_name} {display_name}".lower()
                if self.policy_filter not in combined:
                    continue

            raw_key_path = policy.get("key", "") or ""
            key_parent_path, derived_tail = self._split_key_tail(raw_key_path)
            explicit_value_name = policy.get("valueName")

            elements = self._parse_elements(policy, q, admx_path.stem)
            needs_parent_value = self._elements_require_parent_value(elements)

            key_name_field: Optional[str] = None
            value_field: Optional[str] = explicit_value_name or ""
            key_path_for_entries = raw_key_path

            if explicit_value_name:
                if not needs_parent_value and elements:
                    key_name_field = explicit_value_name
                    value_field = ""
                else:
                    value_field = explicit_value_name
            elif derived_tail:
                if needs_parent_value:
                    value_field = derived_tail
                    key_path_for_entries = key_parent_path
                else:
                    key_name_field = derived_tail
            else:
                value_field = ""

            if key_name_field is not None and not self._key_and_element_share_name(key_name_field, elements):
                key_path_for_entries = self._ensure_key_suffix(key_path_for_entries, key_name_field)

            key_path_entries = self._build_key_paths(policy_class, key_path_for_entries)
            records = {
                "File": admx_path.name,
                "CategoryName": category_name,
                "PolicyName": policy_name,
                "NameSpace": target_namespace,
                "Supported": supported or "Not specified",
                "DisplayName": display_name,
                "ExplainText": explain_text,
                "KeyPath": key_path_entries,
            }
            if value_field:
                records["ValueName"] = value_field
            records["Elements"] = elements
            yield records

    def _collect_supported_definitions(self, root: Any, q, admx_base_name: str) -> None:
        supported_node = root.find(q("supportedOn"))
        if supported_node is None:
            return
        definitions_node = supported_node.find(q("definitions"))
        if definitions_node is None:
            return
        for definition in definitions_node.findall(q("definition")):
            raw_name = definition.get("name", "")
            if not raw_name:
                continue
            display_value = definition.get("displayName", "")
            if not display_value:
                display_node = definition.find(q("displayName"))
                if display_node is not None:
                    display_value = display_node.text or ""
            resolved = self._clean_text(self._resolve_string(display_value, admx_base_name))
            if not resolved:
                continue
            key = self._supported_lookup_key(raw_name)
            if key and key not in self._supported_text_cache:
                self._supported_text_cache[key] = resolved

    def _parse_elements(self, policy: Any, q, admx_base_name: str) -> List[Dict[str, object]]:
        result: List[Dict[str, object]] = []
        elements_node = policy.find(q("elements"))
        if elements_node is not None:
            for element in elements_node:
                tag = self._local_name(element.tag)
                if tag == "decimal":
                    result.append(
                        {
                            "Type": "Decimal",
                            "ValueName": element.get("valueName"),
                            "MinValue": element.get("minValue"),
                            "MaxValue": element.get("maxValue"),
                        }
                    )
                elif tag == "boolean":
                    true_value = self._extract_simple_value(element.find(q("trueValue")), q)
                    false_value = self._extract_simple_value(element.find(q("falseValue")), q)
                    result.append(
                        {
                            "Type": "Boolean",
                            "ValueName": element.get("valueName"),
                            "TrueValue": true_value if true_value is not None else "1",
                            "FalseValue": false_value if false_value is not None else "0",
                        }
                    )
                elif tag == "enum":
                    items = []
                    for item in element.findall(q("item")):
                        display_name = self._resolve_string(item.get("displayName", ""), admx_base_name)
                        value = self._extract_enum_value(item, q)
                        items.append({"DisplayName": display_name, "Data": value})
                    result.append(
                        {
                            "Type": "Enum",
                            "ValueName": element.get("valueName"),
                            "Items": items,
                        }
                    )
                elif tag == "text":
                    result.append(
                        {
                            "Type": "Text",
                            "ValueName": element.get("valueName"),
                        }
                    )
                elif tag == "list":
                    result.append(
                        {
                            "Type": "List",
                            "ValueName": element.get("valueName"),
                        }
                    )

        for tag_name, label in (
            ("enabledValue", "EnabledValue"),
            ("disabledValue", "DisabledValue"),
            ("trueValue", "TrueValue"),
            ("falseValue", "FalseValue"),
        ):
            node = policy.find(q(tag_name))
            if node is None:
                continue
            value = self._extract_simple_value(node, q)
            if value is not None:
                result.append({"Type": label, "Data": value})

        return result

    def _extract_enum_value(self, item: Any, q) -> Optional[str]:
        value_node = item.find(q("value"))
        if value_node is None:
            return None
        decimal_node = value_node.find(q("decimal"))
        if decimal_node is not None:
            return decimal_node.get("value")
        string_node = value_node.find(q("string"))
        if string_node is not None:
            return (string_node.text or "").strip()
        if "value" in value_node.attrib:
            return value_node.get("value")
        return None

    def _extract_simple_value(self, node: Optional[Any], q) -> Optional[str]:
        if node is None:
            return None
        decimal_node = node.find(q("decimal"))
        if decimal_node is not None:
            return decimal_node.get("value")
        string_node = node.find(q("string"))
        if string_node is not None:
            return (string_node.text or "").strip()
        if "value" in node.attrib:
            return node.get("value")
        return None

    def _resolve_string(self, raw_value: str, admx_base_name: str) -> str:
        if not raw_value:
            return ""

        def replace(match: re.Match[str]) -> str:
            string_id = match.group("id")
            text = self._get_string(admx_base_name, string_id)
            return text if text is not None else string_id

        return STRING_TOKEN.sub(replace, raw_value)

    def _get_string(self, admx_base_name: str, string_id: str) -> Optional[str]:
        for language in self.languages:
            cache_key = (admx_base_name.lower(), language.lower())
            table = self._string_cache.get(cache_key)
            if table is None:
                table = self._load_adml_strings(admx_base_name, language)
                self._string_cache[cache_key] = table
            if string_id in table:
                return table[string_id]
        return None

    def _load_adml_strings(self, admx_base_name: str, language: str) -> Dict[str, str]:
        directory = self._resolve_language_directory(language)
        adml_path = directory / f"{admx_base_name}.adml"
        if not adml_path.exists():
            return {}
        try:
            tree = _load_xml_tree(adml_path)
        except et.ParseError as exc:
            LOG.warning(f"Unable to parse ADML {adml_path.name}: {exc}")
            return {}
        except LookupError as exc:
            LOG.warning(f"Unsupported ADML encoding in {adml_path.name}: {exc}")
            return {}
        root = cast(et.Element, tree.getroot())
        namespace = self._extract_namespace(root)
        q = lambda tag: f"{{{namespace}}}{tag}" if namespace else tag
        string_table = root.find(f".//{q('stringTable')}")
        if string_table is None:
            return {}
        table: Dict[str, str] = {}
        for node in string_table.findall(q("string")):
            string_id = node.get("id")
            if not string_id:
                continue
            text = (node.text or "").strip()
            if text:
                table[string_id] = text
        return table

    def _resolve_language_directory(self, language: str) -> Path:
        candidate = self.definitions_path / language
        if candidate.exists():
            return candidate
        lower = language.casefold()
        for directory in self._language_dirs:
            if directory.name.casefold() == lower:
                return directory
        return candidate

    def _extract_supported(self, policy: Any, q, admx_base_name: str) -> str:
        supported_node = policy.find(q("supportedOn"))
        if supported_node is None:
            return ""
        ref = supported_node.get("ref", "")
        code = self._strip_supported_prefix(ref)
        description = self._lookup_supported_description(ref, admx_base_name)
        if code and description:
            return f"{code} - {description}"
        return description or code

    def _lookup_supported_description(self, ref: str, admx_base_name: str) -> Optional[str]:
        key = self._supported_lookup_key(ref)
        if not key:
            return None
        description = self._supported_text_cache.get(key)
        if description:
            return description
        prefixed = self._strip_prefix(ref).strip()
        if prefixed:
            fallback = self._get_string(admx_base_name, prefixed)
            if fallback:
                cleaned = self._clean_text(fallback)
                if cleaned:
                    self._supported_text_cache[key] = cleaned
                    return cleaned
        return None

    def _looks_obsolete(self, explain_text: str, supported: str) -> bool:
        text = f"{explain_text} {supported}".upper()
        return any(flag in text for flag in ("OBSOLetE", "DEPRECATED", "UNSUPPORTED"))

    def _compute_languages(self, explicit: Optional[Sequence[str]]) -> List[str]:
        if explicit:
            return list(dict.fromkeys(lang for lang in explicit if lang))
        discovered = [
            path.name
            for path in self.definitions_path.iterdir()
            if path.is_dir() and path.name.lower() != "en-us"
        ]
        discovered.sort()
        discovered.append("en-US")
        return discovered or ["en-US"]

    def _extract_namespace(self, node: Any) -> str:
        if "}" in node.tag:
            return node.tag.split("}", 1)[0].strip("{")
        return ""

    def _local_name(self, tag: str) -> str:
        return tag.split("}", 1)[1] if "}" in tag else tag

    def _clean_text(self, value: str) -> str:
        return re.sub(r"\s+", " ", value or "").strip()

    def _strip_prefix(self, value: str) -> str:
        return value.split(":", 1)[1] if ":" in value else value

    def _strip_supported_prefix(self, value: str) -> str:
        trimmed = self._strip_prefix((value or "").strip())
        upper = trimmed.upper()
        if upper.startswith("SUPPORTED_"):
            return trimmed[len("SUPPORTED_") :]
        return trimmed

    def _supported_lookup_key(self, value: str) -> str:
        normalized = self._strip_supported_prefix(value or "")
        return normalized.casefold()

    def _build_key_paths(self, policy_class: str, key_path: str) -> List[str]:
        if not key_path:
            return []
        normalized = key_path.lstrip("\\")
        hive_map = {
            "machine": ["HKLM"],
            "user": ["HKCU"],
            "both": ["HKLM", "HKCU"],
        }
        hives = hive_map.get((policy_class or "").lower())
        if not hives:
            hives = ["HKLM"]
        return [f"{hive}\\{normalized}" for hive in hives]

    def _split_key_tail(self, key_path: str) -> Tuple[str, Optional[str]]:
        normalized = key_path.rstrip("\\")
        if not normalized or "\\" not in normalized:
            return normalized, None
        parent, tail = normalized.rsplit("\\", 1)
        return parent, tail

    def _elements_require_parent_value(self, elements: List[Dict[str, object]]) -> bool:
        if not elements:
            return True
        parent_types = {"EnabledValue", "DisabledValue", "TrueValue", "FalseValue"}
        for element in elements:
            element_type = element.get("Type")
            if element_type in parent_types:
                return True
            value_name = element.get("ValueName")
            if not value_name and element_type not in parent_types:
                return True
        return False

    def _ensure_key_suffix(self, key_path: str, suffix: str) -> str:
        suffix = (suffix or "").strip("\\")
        normalized = key_path.rstrip("\\")
        if not normalized:
            return suffix
        if not suffix:
            return normalized
        parts = normalized.split("\\")
        if parts[-1].lower() == suffix.lower():
            return normalized
        return f"{normalized}\\{suffix}"

    def _key_and_element_share_name(self, key_name: str, elements: List[Dict[str, object]]) -> bool:
        if not key_name or not elements:
            return False
        key_lower = key_name.lower()
        for element in elements:
            value_name = element.get("ValueName")
            if isinstance(value_name, str) and value_name.lower() == key_lower:
                return True
        return False

def print_summary(policies: List[Dict[str, object]]) -> None:
    if not policies:
        return
    total = len(policies)
    counter = Counter(_infer_class(policy) for policy in policies)
    summary = ", ".join(f"{key}: {counter[key]}" for key in sorted(counter.keys()))
    print()
    print(f"Policies: {total}")
    print(f"By Class: {summary}")

def _infer_class(policy: Dict[str, object]) -> str:
    key_path = policy.get("KeyPath")
    if isinstance(key_path, list):
        keys = set("HKCU" if path.upper().startswith("HKCU\\") else "HKLM" for path in key_path)
        if "HKLM" in keys and "HKCU" in keys:
            return "Both"
        if "HKLM" in keys:
            return "Machine"
        if "HKCU" in keys:
            return "User"
    return "Unknown"

def _serialize_json(payload: List[Dict[str, object]], *, pretty: bool) -> str:
    if not pretty:
        return json.dumps(payload)
    prepared_payload, inline_map = _prepare_inline_elements(payload)
    serialized = json.dumps(prepared_payload, indent=2)
    if not inline_map:
        return serialized
    return _inject_inline_elements(serialized, inline_map, indent_width=2)

def _prepare_inline_elements(payload: List[Dict[str, object]]):
    inline_map: Dict[str, List[Dict[str, object]]] = {}
    prepared: List[Dict[str, object]] = []
    for policy in payload:
        record = dict(policy)
        elements = record.get("Elements")
        if isinstance(elements, list):
            marker = f"__INLINE_ELEMENTS_{len(inline_map)}__"
            inline_map[marker] = elements
            record["Elements"] = marker
        prepared.append(record)
    return prepared, inline_map

def _inject_inline_elements(serialized: str, inline_map: Dict[str, List[Dict[str, object]]], *, indent_width: int) -> str:
    def replacer(match: re.Match[str]) -> str:
        marker = match.group("marker")
        elements = inline_map.get(marker)
        if elements is None:
            return match.group(0)
        indent = match.group("indent")
        trailing = match.group("trailing")
        formatted = _format_inline_elements(elements, indent, indent_width)
        return f'{indent}"Elements": {formatted}{trailing}'

    return INLINE_ELEMENTS_PATTERN.sub(replacer, serialized)

def _format_inline_elements(elements: List[Dict[str, object]], indent: str, indent_width: int) -> str:
    if not elements:
        return "[]"
    indent_unit = " " * indent_width
    inner_indent = indent + indent_unit
    encoded_items = [
        _format_inline_element(element, inner_indent, indent_width)
        for element in elements
    ]
    body = ",\n".join(encoded_items)
    return "[\n" + body + "\n" + indent + "]"

def _format_inline_element(element: Dict[str, object], element_indent: str, indent_width: int) -> str:
    encoded = _inline_object_string(element)
    complex_keys = [key for key, value in element.items() if isinstance(value, list)]
    if not complex_keys:
        return f"{element_indent}{encoded}"
    for key in complex_keys:
        value = element[key]
        if not isinstance(value, list):
            continue
        formatted_list = _format_nested_list(value, element_indent, indent_width)
        raw = json.dumps(value, separators=(", ", ": "))
        encoded = encoded.replace(f'"{key}": {raw}', f'"{key}": {formatted_list}', 1)
    if encoded.endswith(" }"):
        encoded = encoded[:-2] + "\n" + element_indent + "}"
    return f"{element_indent}{encoded}"

def _format_nested_list(values: List[object], element_indent: str, indent_width: int) -> str:
    if not values:
        return "[]"
    indent_unit = " " * indent_width
    list_indent = element_indent + indent_unit
    entry_indent = element_indent + (indent_unit * 2)
    formatted_entries = []
    for entry in values:
        if isinstance(entry, dict):
            entry_text = _inline_object_string(entry)
        else:
            entry_text = json.dumps(entry)
        formatted_entries.append(f"{entry_indent}{entry_text}")
    return "[\n" + ",\n".join(formatted_entries) + "\n" + list_indent + "]"

def _inline_object_string(value: Dict[str, object]) -> str:
    encoded = json.dumps(value, separators=(", ", ": "))
    if encoded.startswith("{") and encoded.endswith("}"):
        inner = encoded[1:-1].strip()
        encoded = f"{{ {inner} }}"
    return encoded

def write_payload(path: Path, payload: List[Dict[str, object]], *, fmt: str, pretty: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "yaml":
        if yaml is None:
            raise SystemExit("YAML output requires the 'PyYAML' package. Install it with 'pip install pyyaml'.")
        serialized = yaml.safe_dump(
            payload,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )
    else:
        serialized = _serialize_json(payload, pretty=pretty)
    path.write_text(serialized, encoding="utf-8")

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    admx_parser = AdmxParser(
        definitions_path=args.definitions,
        languages=args.languages,
        ignored_admx=args.ignored_admx,
        include_obsolete=args.include_obsolete,
        class_filter=args.class_filter,
        category_filter=args.category_filter,
        policy_filter=args.policy_filter,
    )
    policies = admx_parser.parse()

    pretty_output = not args.compress
    output_format = args.format
    if output_format == "yaml":
        if not pretty_output:
            LOG.info("--compress is ignored for YAML output.")
        pretty_output = True
    output_path = args.output
    if output_path is None:
        output_path = Path("Policies.yaml" if output_format == "yaml" else "Policies.json")
    write_payload(output_path, policies, fmt=output_format, pretty=pretty_output)

    print(f"Wrote {len(policies)} policies to {output_path}")
    print_summary(policies)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
