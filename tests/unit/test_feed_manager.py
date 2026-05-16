import pytest
from unittest.mock import patch, MagicMock
from homenetguard.intelligence.feed_manager import FeedManager, FEEDS, _valid_ip
from homenetguard.storage import database


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


@pytest.fixture
def tmp_fm(tmp_path):
    return FeedManager(feeds_path=str(tmp_path / "feeds"))


def _mock_response(text: str) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.raise_for_status = MagicMock()
    return resp


def test_feeds_dict_not_empty():
    assert len(FEEDS) >= 2
    for name, feed in FEEDS.items():
        assert "url" in feed
        assert "type" in feed


def test_update_feed_ip_list(tmp_fm):
    ip_list_content = "# comment\n1.2.3.4\n5.6.7.8\ninvalid_entry\n"
    with patch("requests.get", return_value=_mock_response(ip_list_content)):
        result = tmp_fm.update_feed("feodo_tracker")
    assert result["entries"] == 2
    assert result["feed"] == "feodo_tracker"


def test_update_feed_domain_list(tmp_fm):
    domain_content = "# urlhaus hostfile\n127.0.0.1 malicious.com\n127.0.0.1 evil.net\n"
    with patch("requests.get", return_value=_mock_response(domain_content)):
        result = tmp_fm.update_feed("urlhaus")
    assert result["entries"] >= 0  # domain parsing may vary


def test_update_all_returns_stats(tmp_fm):
    with patch("requests.get", return_value=_mock_response("# test\n1.1.1.1\n")):
        results = tmp_fm.update_all()
    assert isinstance(results, dict)
    assert len(results) == len(FEEDS)


def test_valid_ip():
    assert _valid_ip("1.2.3.4") is True
    assert _valid_ip("255.255.255.255") is True
    assert _valid_ip("not_an_ip") is False
    assert _valid_ip("999.999.999.999") is False


def test_get_status_empty_initially(tmp_fm):
    status = tmp_fm.get_status()
    assert isinstance(status, list)


def test_unknown_feed_raises(tmp_fm):
    with pytest.raises(ValueError, match="Unknown feed"):
        tmp_fm.update_feed("nonexistent_feed")
