"""Small, dependency-free JSON Schema validator for the checked-in schemas.

The release harness must fail closed when an artifact is malformed.  The
schemas in this repository intentionally use a small Draft 2020-12 subset;
this validator implements that subset so validation does not disappear when a
third-party Python package is unavailable.
"""

from __future__ import annotations

import datetime as _datetime
import json
import re
from pathlib import Path
from typing import Any


class SchemaError(ValueError):
    """Raised when a document does not satisfy a checked-in schema."""


def load_schema(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaError(f"cannot load schema {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SchemaError(f"schema {path} is not a JSON object")
    return value


def _type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def validate(document: Any, schema: dict[str, Any], *, schema_root: dict[str, Any] | None = None, path: str = "$", seen: set[int] | None = None) -> None:
    """Validate *document* against a checked-in schema or raise SchemaError."""
    root = schema_root or schema
    if seen is None:
        seen = set()
    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise SchemaError(f"{path}: unsupported schema reference {ref!r}")
        target: Any = root
        for part in ref[2:].split("/"):
            target = target[part]
        validate(document, target, schema_root=root, path=path, seen=seen)
        return
    if "const" in schema and document != schema["const"]:
        raise SchemaError(f"{path}: expected {schema['const']!r}, got {document!r}")
    if "enum" in schema and document not in schema["enum"]:
        raise SchemaError(f"{path}: expected one of {schema['enum']!r}, got {document!r}")
    if "type" in schema:
        expected = schema["type"]
        types = expected if isinstance(expected, list) else [expected]
        if not any(_type_matches(document, item) for item in types):
            raise SchemaError(f"{path}: expected type {expected!r}, got {type(document).__name__}")
    if isinstance(document, str):
        if "pattern" in schema and re.search(schema["pattern"], document) is None:
            raise SchemaError(f"{path}: does not match {schema['pattern']!r}")
        if schema.get("format") == "date-time":
            try:
                _datetime.datetime.fromisoformat(document.replace("Z", "+00:00"))
            except ValueError as exc:
                raise SchemaError(f"{path}: invalid date-time") from exc
        if "minLength" in schema and len(document) < schema["minLength"]:
            raise SchemaError(f"{path}: string is too short")
    if isinstance(document, (int, float)) and not isinstance(document, bool):
        if "minimum" in schema and document < schema["minimum"]:
            raise SchemaError(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and document > schema["maximum"]:
            raise SchemaError(f"{path}: above maximum {schema['maximum']}")
    if isinstance(document, list):
        if "minItems" in schema and len(document) < schema["minItems"]:
            raise SchemaError(f"{path}: too few items")
        if "maxItems" in schema and len(document) > schema["maxItems"]:
            raise SchemaError(f"{path}: too many items")
        if schema.get("uniqueItems"):
            rendered = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in document]
            if len(set(rendered)) != len(rendered):
                raise SchemaError(f"{path}: items are not unique")
        if "items" in schema:
            for index, item in enumerate(document):
                validate(item, schema["items"], schema_root=root, path=f"{path}[{index}]", seen=seen)
    if isinstance(document, dict):
        for required in schema.get("required", []):
            if required not in document:
                raise SchemaError(f"{path}: missing required property {required!r}")
        for key, subschema in schema.get("properties", {}).items():
            if key in document:
                validate(document[key], subschema, schema_root=root, path=f"{path}.{key}", seen=seen)


def validate_file(document_path: Path, schema_path: Path) -> Any:
    try:
        document = json.loads(document_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaError(f"cannot load JSON {document_path}: {exc}") from exc
    validate(document, load_schema(schema_path))
    return document
