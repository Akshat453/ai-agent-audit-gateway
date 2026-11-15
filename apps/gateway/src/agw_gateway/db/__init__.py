"""Database access: engine construction and SQLAlchemy Core table definitions."""

from agw_gateway.db.session import create_db_engine, is_db_unavailable

__all__ = ["create_db_engine", "is_db_unavailable"]
