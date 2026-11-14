"""Unlisted globals of one file scan under the strict globals policy (T029, FR-008, research S7)."""

from __future__ import annotations

from typing import Any

from model_dependabot.assurance import globals_policy

SAFE = globals_policy.SafeList(
    version=1,
    sha256="0" * 64,
    entries=frozenset({("collections", "OrderedDict"), ("torch", "Size")}),
)


def _scan(*globals_: tuple[str, str, str], complete: bool = True) -> dict[str, Any]:
    return {
        "complete": complete,
        "globals": [{"module": m, "name": n, "safety": s} for m, n, s in globals_],
    }


def _exception(module: str, name: str, exception_id: int = 1) -> dict[str, Any]:
    return {"exception_id": exception_id, "module": module, "name": name}


MIXED = _scan(
    ("collections", "OrderedDict", "innocuous"),
    ("model_dependabot_fixture.layers", "CustomLayer", "suspicious"),
    ("os", "system", "dangerous"),
)


def test_unlisted_holds_every_global_not_safe_listed_whatever_its_label() -> None:
    assert globals_policy.unlisted(MIXED, SAFE, []) == [
        "model_dependabot_fixture.layers.CustomLayer",
        "os.system",
    ]


def test_an_innocuous_global_not_on_the_safe_list_is_unlisted() -> None:
    scan = _scan(("numpy", "dtype", "innocuous"))
    assert globals_policy.unlisted(scan, SAFE, []) == ["numpy.dtype"]


def test_an_exception_removes_its_global_and_is_reported_as_excepted() -> None:
    active = [_exception("os", "system", 4), _exception("os", "popen", 5)]
    assert globals_policy.unlisted(MIXED, SAFE, active) == [
        "model_dependabot_fixture.layers.CustomLayer"
    ]
    assert [e["exception_id"] for e in globals_policy.excepted(MIXED, SAFE, active)] == [4]


def test_matching_is_exact() -> None:
    scan = _scan(("builtins", "getattr", "dangerous"))
    assert globals_policy.unlisted(scan, SAFE, [_exception("__builtin__", "getattr")]) == [
        "builtins.getattr"
    ]


def test_an_unknown_global_always_stays_unlisted() -> None:
    scan = _scan(("unknown", "eval", "dangerous"))
    listing = globals_policy.SafeList(1, "0" * 64, frozenset({("unknown", "eval")}))
    assert globals_policy.unlisted(scan, listing, [_exception("unknown", "eval")]) == [
        "unknown.eval"
    ]


def test_an_incomplete_scan_is_never_clean() -> None:
    assert globals_policy.is_clean(_scan(("torch", "Size", "suspicious")), SAFE, [])
    assert not globals_policy.is_clean(
        _scan(("torch", "Size", "suspicious"), complete=False), SAFE, []
    )
    assert not globals_policy.is_clean(MIXED, SAFE, [])
