import pytest
from core.database import DeltaDB
from unittest.mock import MagicMock

@pytest.fixture
def mock_db(tmp_path):
    """Provides an isolated file-based database for testing."""
    # tmp_path is a built-in pytest fixture that creates a temporary directory
    db_file = tmp_path / "test_uro.db"
    db = DeltaDB(db_path=str(db_file))
    return db

@pytest.fixture
def mock_llm():
    """Provides a mocked TriageAgent so we don't call Ollama during tests."""
    mock_agent = MagicMock()
    mock_agent.run.return_value = "Surface is secure. No actionable bug bounty intelligence found."
    return mock_agent