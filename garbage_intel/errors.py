"""Application errors shared by the storage, service and HTTP layers."""

from __future__ import annotations


class AppError(ValueError):
    """A safe, user-displayable error with an HTTP status mapping."""

    status = 400
    code = "VALIDATION_ERROR"


class ValidationError(AppError):
    status = 400
    code = "VALIDATION_ERROR"


class NotFoundError(AppError):
    status = 404
    code = "NOT_FOUND"


class ConflictError(AppError):
    status = 409
    code = "CONFLICT"


class ModuleDisabledError(AppError):
    status = 409
    code = "MODULE_DISABLED"
