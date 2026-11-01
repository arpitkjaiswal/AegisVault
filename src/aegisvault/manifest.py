"""Strict immutable manifest and canonical, type-preserving JSON values."""

import hashlib
import json
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .errors import InvalidDocument, InvalidManifest


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class FieldSpec(StrictModel):
    kind: Literal["string", "integer", "boolean", "date", "json"]
    nullable: bool = False
    search: Literal["none", "exact"] = "none"
    normalize: Literal["identity", "casefold"] = "identity"
    accept_equality_leakage: bool = False

    @model_validator(mode="after")
    def valid_search(self):
        if self.search == "exact" and not self.accept_equality_leakage:
            raise ValueError("exact search requires leakage acceptance")
        if self.normalize == "casefold" and self.kind != "string":
            raise ValueError("casefold requires string")
        return self

    def validate_value(self, value: object) -> None:
        if value is None:
            if not self.nullable:
                raise InvalidDocument()
            return
        valid = {
            "string": type(value) is str,
            "integer": type(value) is int,
            "boolean": type(value) is bool,
            "date": type(value) is str,
            "json": type(value) in (dict, list, str, int, float, bool),
        }[self.kind]
        if not valid:
            raise InvalidDocument()
        if self.kind == "date":
            try:
                if date.fromisoformat(value).isoformat() != value:
                    raise ValueError()
            except (ValueError, TypeError):
                raise InvalidDocument() from None
        try:
            if len(canonical(value)) > 128 * 1024:
                raise InvalidDocument()
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise InvalidDocument() from None

    def normalized(self, value: object) -> bytes:
        self.validate_value(value)
        if self.normalize == "casefold" and value is not None:
            value = value.casefold()
        return canonical(value)


class CollectionSpec(StrictModel):
    fields: dict[str, FieldSpec] = Field(min_length=1, max_length=64)
    roles: dict[str, list[str]]
    purposes: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_contract(self):
        if set(self.roles) != {"read", "write", "search", "delete", "rotate"}:
            raise ValueError("all operation roles must be declared")
        if any(not isinstance(v, str) or not v or len(v) > 128 for v in self.fields):
            raise ValueError("invalid field name")
        if any(not v for values in self.roles.values() for v in values):
            raise ValueError("empty role")
        return self

    def validate_document(self, document: dict) -> None:
        if type(document) is not dict or set(document) != set(self.fields):
            raise InvalidDocument()
        for name, spec in self.fields.items():
            spec.validate_value(document[name])
        if len(canonical(document)) > 256 * 1024:
            raise InvalidDocument()


class Manifest(StrictModel):
    version: Literal[1]
    project: str = Field(min_length=1, max_length=128)
    collections: dict[str, CollectionSpec] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def valid_names(self):
        for name in [self.project, *self.collections]:
            if not name or len(name) > 128 or any(ord(c) < 32 for c in name):
                raise ValueError("invalid identifier")
        return self

    @classmethod
    def load(cls, source: str | bytes):
        def unique_object(pairs):
            result = {}
            for name, value in pairs:
                if name in result:
                    raise ValueError("duplicate manifest key")
                result[name] = value
            return result

        try:
            if len(source) > 1024 * 1024:
                raise ValueError("manifest too large")
            return cls.model_validate(json.loads(source, object_pairs_hook=unique_object))
        except (ValidationError, ValueError, TypeError, RecursionError, UnicodeError):
            raise InvalidManifest() from None

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(canonical(self.model_dump())).hexdigest()

    def leakage_report(self) -> dict:
        return {
            "project": self.project,
            "fingerprint": self.fingerprint,
            "always_visible": [
                "tenant, collection and record identifiers",
                "record count and size",
                "access patterns",
                "key generation and revision",
                "audit metadata",
            ],
            "exact_search": [
                {
                    "collection": c,
                    "field": f,
                    "normalization": s.normalize,
                    "leakage": (
                        "equality/frequency within a tenant and field; query access patterns"
                    ),
                }
                for c, spec in self.collections.items()
                for f, s in spec.fields.items()
                if s.search == "exact"
            ],
            "limitations": [
                "no hostile-database completeness or freshness guarantee",
                "small-domain searchable values can be guessed using frequency/auxiliary data",
            ],
        }
