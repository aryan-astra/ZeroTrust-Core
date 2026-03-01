"""
ZeroTrust - Test Configuration
Forces SQLite for test isolation, initializes tables before test session.
"""

import os
import sys

# Override database to use in-memory SQLite BEFORE any app imports
os.environ["ZEROTRUST_TEST"] = "1"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from data.database import init_db, get_engine, Base, _get_database_url

# Patch database to use SQLite for tests
import data.database as db_mod


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Create a fresh SQLite database for the entire test session."""
    # Force SQLite by resetting engine state and patching _get_database_url
    db_mod._engine = None
    db_mod._SessionLocal = None

    sqlite_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "test_zerotrust.db")
    os.makedirs(os.path.dirname(sqlite_path), exist_ok=True)

    # Remove old test DB if exists
    if os.path.exists(sqlite_path):
        os.remove(sqlite_path)

    test_url = f"sqlite:///{sqlite_path}"

    # Patch to force SQLite
    original_get_url = db_mod._get_database_url
    db_mod._get_database_url = lambda: test_url

    # Initialize
    init_db()

    yield

    # Cleanup
    db_mod._get_database_url = original_get_url
    if db_mod._engine:
        db_mod._engine.dispose()
    db_mod._engine = None
    db_mod._SessionLocal = None
    try:
        if os.path.exists(sqlite_path):
            os.remove(sqlite_path)
    except PermissionError:
        pass  # Windows file lock — harmless
