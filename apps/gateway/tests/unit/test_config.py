"""Task 2: config fails at startup naming the variable, never echoing values."""

from pathlib import Path

import pytest

from agw_gateway.config import ConfigError, load_settings

pytestmark = pytest.mark.unit

SECRET = "postgresql+psycopg://agw_app:SUPERSECRETVALUE@db:5432/agw"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    for k in list(os.environ):
        if k.startswith("AGW_"):
            monkeypatch.delenv(k)


def test_missing_database_url_names_variable_without_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGW_ENV", "dev")
    monkeypatch.setenv("AGW_MIGRATOR_DATABASE_URL", SECRET)
    with pytest.raises(ConfigError) as exc:
        load_settings()
    msg = str(exc.value)
    assert "AGW_DATABASE_URL (missing)" in msg
    assert "SUPERSECRETVALUE" not in msg
    assert exc.value.__cause__ is None  # pydantic error (with inputs) is not chained


def test_invalid_value_is_named_not_echoed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGW_ENV", "SUPERSECRETVALUE")
    monkeypatch.setenv("AGW_DATABASE_URL", SECRET)
    with pytest.raises(ConfigError) as exc:
        load_settings()
    assert "AGW_ENV (invalid)" in str(exc.value)
    assert "SUPERSECRETVALUE" not in str(exc.value)


def test_secret_is_secretstr_and_file_variant(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    f = tmp_path / "db_url"
    f.write_text(SECRET + "\n")
    monkeypatch.setenv("AGW_ENV", "test")
    monkeypatch.setenv("AGW_DATABASE_URL_FILE", str(f))
    s = load_settings()
    assert s.database_url.get_secret_value() == SECRET
    assert "SUPERSECRETVALUE" not in repr(s)


def test_lease_must_exceed_adapter_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGW_ENV", "dev")
    monkeypatch.setenv("AGW_DATABASE_URL", SECRET)
    with pytest.raises(ConfigError):
        load_settings(lease_seconds=5, adapter_timeout_seconds=10)
