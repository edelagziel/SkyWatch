from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


@dataclass(frozen=True, slots=True)
class GuardResult:
    missing_paths: list[str]


class NormalizationGuard:
    """
    Validates presence of required fields/paths.

    Path syntax: dot-separated, starting at snapshot dict root
    (e.g. "metadata.encryption.enabled").
    """

    @staticmethod
    def require(snapshot_dict: Mapping[str, Any], paths: Sequence[str]) -> GuardResult:
        missing: list[str] = []
        for p in paths:
            if not _has_path(snapshot_dict, p):
                missing.append(p)
        return GuardResult(missing_paths=missing)


def _has_path(obj: Mapping[str, Any], path: str) -> bool:
    cur: Any = obj
    for part in path.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return False
    return True
