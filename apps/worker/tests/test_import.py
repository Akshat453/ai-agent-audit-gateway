import pytest


@pytest.mark.unit
def test_worker_package_imports() -> None:
    import agw_worker
    import agw_worker.outbox

    assert agw_worker.__doc__
