from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..errors import RuleInvalidSchema, RuleSkippedMissingData


def get_required(metadata: Mapping[str, Any], *, rule_id: str, key: str) -> Any:
    if key not in metadata:
        raise RuleSkippedMissingData(rule_id, [f"metadata.{key}"])
    return metadata[key]


def get_optional(metadata: Mapping[str, Any], key: str) -> Any | None:
    return metadata.get(key)


def require_mapping(value: Any, *, rule_id: str, path: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    raise RuleInvalidSchema(rule_id, f"Expected object at {path}")


def require_list(value: Any, *, rule_id: str, path: str) -> list[Any]:
    if isinstance(value, list):
        return value
    raise RuleInvalidSchema(rule_id, f"Expected list at {path}")


def as_bool(value: Any, *, rule_id: str, path: str) -> bool:
    if isinstance(value, bool):
        return value
    raise RuleInvalidSchema(rule_id, f"Expected boolean at {path}")


AWS_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AWS_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def is_public_grantee_uri(uri: str | None) -> bool:
    return uri in (AWS_ALL_USERS_URI, AWS_AUTH_USERS_URI)


def normalize_to_list(v: Any) -> list[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]
