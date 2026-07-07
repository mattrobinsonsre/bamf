"""Guard rails on dependency pins that would otherwise break silently.

These read pyproject.toml and assert structural invariants — cheap
source-introspection, no install, no import. They exist to make a few
load-bearing dependency decisions explicit and hard to undo by accident.
"""

from __future__ import annotations

import pathlib
import tomllib

_PYPROJECT = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"


def _deps() -> dict[str, object]:
    return tomllib.loads(_PYPROJECT.read_text())["tool"]["poetry"]["dependencies"]


def _version_spec(spec: object) -> str:
    # A dependency value is either a bare version string or a table with a
    # `version` key (e.g. uvicorn = {extras = [...], version = "..."}).
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        return str(spec.get("version", ""))
    return ""


def _has_upper_bound(spec: str) -> bool:
    # A caret (`^`) implies an upper bound; an explicit `<` is one too.
    return spec.startswith("^") or "<" in spec


def test_starlette_is_directly_pinned_with_upper_bound() -> None:
    """starlette MUST be a direct dependency with an explicit upper bound.

    fastapi only floors starlette (``starlette>=0.46``, no ceiling), so without
    our own cap it floats to the newest release on every build — it has already
    jumped to 1.x. A starlette major can then change ASGI/framework behaviour
    with no deliberate bump on our side, and a fastapi bump can drag a new
    starlette in silently. Pinning it directly forces every starlette move to be
    an explicit, reviewed edit.

    If you are intentionally taking a new starlette, bump the pin in
    pyproject.toml — do not delete it or its upper bound.
    """
    deps = _deps()
    assert "starlette" in deps, (
        "starlette must be a DIRECT dependency in pyproject.toml, not left as a "
        "floor-only transitive of fastapi"
    )
    spec = _version_spec(deps["starlette"])
    assert _has_upper_bound(spec), f"starlette needs an explicit upper bound; got {spec!r}"


def test_fastapi_has_upper_bound() -> None:
    """fastapi must keep an upper bound — it ships breaking changes in 0.x
    minors, so an unbounded spec would pull them in without review."""
    spec = _version_spec(_deps()["fastapi"])
    assert _has_upper_bound(spec), f"fastapi needs an explicit upper bound; got {spec!r}"


def test_python3_saml_is_present() -> None:
    """python3-saml must stay declared. The SAML connector lazy-imports it
    (`services/bamf/auth/connectors/saml.py`), so its absence isn't caught by
    import at startup — a SAML login would fail only at first use."""
    assert "python3-saml" in _deps(), (
        "python3-saml must remain a dependency — the SAML connector lazy-imports "
        "it, so dropping it breaks SAML login silently rather than at startup"
    )
