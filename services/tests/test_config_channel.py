"""Guard the Helm-values → API-config channel.

The chart renders ``core.api.config`` (in ``helm/bamf/values.yaml``) into the
API's ``config.yaml``; ``Settings`` loads it with ``extra="ignore"``, so a key
that no model field consumes — a rename, or a knob wired to nothing (the #196
class) — is silently dropped rather than rejected. This is exactly the
camelCase-values ↔ snake_case-config boundary BAMF has repeatedly gotten wrong.

This walks the real ``values.yaml`` config block against the Settings model tree
(class-level introspection, no instantiation, no env reads) and fails on any key
that isn't a real field.
"""

from __future__ import annotations

import pathlib
import typing

import yaml
from pydantic import BaseModel

from bamf.config import Settings


def _values_path() -> pathlib.Path:
    # Repo layout puts values.yaml at <root>/helm/bamf/ (parents[2] locally);
    # the test image copies it to /app/helm/bamf/ (parents[1]). Try both.
    here = pathlib.Path(__file__).resolve()
    for up in (2, 1, 3):
        cand = here.parents[up] / "helm" / "bamf" / "values.yaml"
        if cand.exists():
            return cand
    raise FileNotFoundError("helm/bamf/values.yaml not found from " + str(here))


def _config_block() -> dict:
    return yaml.safe_load(_values_path().read_text())["core"]["api"]["config"]


def _model_of(annotation: object) -> type[BaseModel] | None:
    """Return the BaseModel subclass an annotation refers to (unwrapping
    Optional[...] / unions), else None for scalar/leaf fields."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    for arg in typing.get_args(annotation):
        if isinstance(arg, type) and issubclass(arg, BaseModel):
            return arg
    return None


def _check(cfg: dict, model: type[BaseModel], path: str = "") -> list[str]:
    errors: list[str] = []
    fields = model.model_fields
    for key, val in cfg.items():
        where = f"{path}.{key}" if path else key
        if key not in fields:
            errors.append(f"{where} — not a field of {model.__name__}")
            continue
        submodel = _model_of(fields[key].annotation)
        if isinstance(val, dict) and submodel is not None:
            errors.extend(_check(val, submodel, where))
    return errors


def test_values_config_keys_are_real_settings_fields():
    """Every key under core.api.config in values.yaml must map onto a real
    Settings field — otherwise the chart renders a config knob the API ignores."""
    errors = _check(_config_block(), Settings)
    assert not errors, "values.yaml core.api.config → Settings drift:\n" + "\n".join(errors)
