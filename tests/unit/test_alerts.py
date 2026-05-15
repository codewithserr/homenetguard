import pytest
from unittest.mock import patch, MagicMock
from homenetguard.alerts.email_alert import EmailAlert
from homenetguard.alerts.telegram_alert import TelegramAlert
from homenetguard.alerts.notifier import Notifier


# ─── EmailAlert ─────────────────────────────────────────────────
def test_email_disabled_returns_false():
    alert = EmailAlert({"enabled": False})
    assert alert.send("subject", "body") is False


def test_email_missing_config_returns_false():
    alert = EmailAlert({"enabled": True, "smtp_host": "", "smtp_port": 587,
                        "smtp_user": "", "smtp_password": "", "recipient": ""})
    assert alert.send("subject", "body") is False


def test_email_smtp_error_returns_false():
    cfg = {
        "enabled": True, "smtp_host": "smtp.example.com", "smtp_port": 587,
        "smtp_user": "user@example.com", "smtp_password": "pass",
        "recipient": "dest@example.com"
    }
    alert = EmailAlert(cfg)
    with patch("smtplib.SMTP") as mock_smtp:
        mock_smtp.side_effect = Exception("Connection refused")
        result = alert.send("Test subject", "Test body")
    assert result is False


def test_email_success():
    cfg = {
        "enabled": True, "smtp_host": "smtp.example.com", "smtp_port": 587,
        "smtp_user": "user@example.com", "smtp_password": "pass",
        "recipient": "dest@example.com"
    }
    alert = EmailAlert(cfg)
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = lambda s: mock_server
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
        result = alert.send("Test subject", "Test body")
    assert result is True


# ─── TelegramAlert ──────────────────────────────────────────────
def test_telegram_disabled_returns_false():
    alert = TelegramAlert({"enabled": False})
    assert alert.send("message") is False


def test_telegram_missing_token_returns_false():
    alert = TelegramAlert({"enabled": True, "bot_token": "", "chat_id": ""})
    assert alert.send("message") is False


def test_telegram_request_error_returns_false():
    cfg = {"enabled": True, "bot_token": "fake_token", "chat_id": "123"}
    alert = TelegramAlert(cfg)
    with patch("requests.post") as mock_post:
        mock_post.side_effect = Exception("Network error")
        result = alert.send("Test message")
    assert result is False


# ─── Notifier ───────────────────────────────────────────────────
def test_notifier_dispatches_email_for_high():
    cfg = {
        "alerts": {
            "email": {"enabled": True, "min_severity": "high",
                      "smtp_host": "x", "smtp_port": 587, "smtp_user": "u",
                      "smtp_password": "p", "recipient": "r@r.com"},
            "telegram": {"enabled": False, "min_severity": "critical"},
        }
    }
    notifier = Notifier(cfg)
    with patch.object(notifier._email, "send", return_value=True) as mock_send:
        notifier.dispatch("port_scan", "high", "Test desc", src_ip="1.2.3.4")
        mock_send.assert_called_once()


def test_notifier_skips_email_for_low():
    cfg = {
        "alerts": {
            "email": {"enabled": True, "min_severity": "high"},
            "telegram": {"enabled": False, "min_severity": "critical"},
        }
    }
    notifier = Notifier(cfg)
    with patch.object(notifier._email, "send", return_value=True) as mock_send:
        notifier.dispatch("flood", "low", "Low severity")
        mock_send.assert_not_called()


def test_notifier_dispatches_telegram_for_critical():
    cfg = {
        "alerts": {
            "email": {"enabled": False, "min_severity": "high"},
            "telegram": {"enabled": True, "min_severity": "critical",
                         "bot_token": "tok", "chat_id": "123"},
        }
    }
    notifier = Notifier(cfg)
    with patch.object(notifier._telegram, "send", return_value=True) as mock_send:
        notifier.dispatch("blacklisted_ip", "critical", "Critical!")
        mock_send.assert_called_once()
