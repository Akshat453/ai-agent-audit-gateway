"""Engine construction. Sync SQLAlchemy 2 + psycopg 3 (12 §1): explicit transaction control."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError


def create_db_engine(url: str, *, connect_timeout: int = 3, pool_size: int = 10) -> Engine:
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=pool_size * 2,
        pool_timeout=connect_timeout,
        connect_args={"connect_timeout": connect_timeout},
    )


def is_db_unavailable(exc: BaseException) -> bool:
    """True when the error means "the database could not be reached / used" (fail closed: 503)."""
    if isinstance(exc, OperationalError | InterfaceError):
        return True
    if isinstance(exc, DBAPIError) and exc.connection_invalidated:
        return True
    return isinstance(exc, TimeoutError)
