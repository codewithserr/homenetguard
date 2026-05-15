import pytest
from homenetguard.storage import database


@pytest.fixture
def tmp_db(tmp_path):
    db_file = str(tmp_path / "test.db")
    database.init_db(db_file)
    yield db_file
