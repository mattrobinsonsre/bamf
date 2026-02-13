"""Common Pydantic models used across the API."""

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

# DNS-like naming pattern: lowercase alphanumeric + hyphens, start with letter, max 63 chars
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


class BAMFBaseModel(BaseModel):
    """Base model with common configuration."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


class NamedModel(BAMFBaseModel):
    """Base model for entities with DNS-like names."""

    name: str = Field(..., min_length=1, max_length=63)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate name follows DNS-like naming rules."""
        if not NAME_PATTERN.match(v):
            raise ValueError(
                "Name must be lowercase alphanumeric with hyphens, "
                "start with a letter, and be 1-63 characters"
            )
        return v


class TimestampMixin(BAMFBaseModel):
    """Mixin for models with timestamps."""

    created_at: datetime
    updated_at: datetime


class PaginationParams(BAMFBaseModel):
    """Pagination parameters for list endpoints."""

    cursor: str | None = Field(default=None, description="Cursor for pagination")
    limit: int = Field(default=50, ge=1, le=100, description="Number of items per page")


class CursorPage[T](BAMFBaseModel):
    """Cursor-based pagination response."""

    items: list[T]
    next_cursor: str | None = Field(
        default=None, description="Cursor for next page, null if no more pages"
    )
    has_more: bool = Field(description="Whether there are more items")


class SuccessResponse(BAMFBaseModel):
    """Generic success response."""

    success: bool = True
    message: str | None = None
