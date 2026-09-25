"""Tests for per-recipient tracking tokens and attribution."""

from __future__ import annotations

from bluephishproxy.database import (
    get_recipient_by_token,
    get_recipient_stats,
    import_recipients,
    list_recipients,
    record_recipient_click,
    delete_recipient,
)


class TestRecipientImport:
    def test_import_creates_unique_tokens(self, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "alice@example.com", "name": "Alice"},
            {"email": "bob@example.com", "name": "Bob"},
        ])
        assert len(results) == 2
        tokens = {r["token"] for r in results}
        assert len(tokens) == 2

    def test_import_with_department(self, cfg, campaign):
        import_recipients(cfg, campaign["id"], [
            {"email": "carol@example.com", "name": "Carol", "department": "Finance"},
        ])
        recipients = list_recipients(cfg, campaign["id"])
        assert recipients[0]["department"] == "Finance"

    def test_import_minimal_fields(self, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "dave@example.com"},
        ])
        assert results[0]["email"] == "dave@example.com"
        r = get_recipient_by_token(cfg, results[0]["token"])
        assert r["name"] == ""

    def test_lookup_by_token(self, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "eve@example.com", "name": "Eve"},
        ])
        token = results[0]["token"]
        r = get_recipient_by_token(cfg, token)
        assert r is not None
        assert r["email"] == "eve@example.com"
        assert r["status"] == "pending"
        assert r["click_count"] == 0

    def test_lookup_invalid_token(self, cfg):
        r = get_recipient_by_token(cfg, "nonexistent")
        assert r is None

    def test_list_recipients_by_campaign(self, cfg, campaign):
        import_recipients(cfg, campaign["id"], [
            {"email": "f@example.com"},
            {"email": "g@example.com"},
        ])
        recipients = list_recipients(cfg, campaign["id"])
        assert len(recipients) == 2

    def test_delete_recipient(self, cfg, campaign):
        import_recipients(cfg, campaign["id"], [
            {"email": "h@example.com"},
        ])
        recipients = list_recipients(cfg, campaign["id"])
        assert delete_recipient(cfg, recipients[0]["id"])
        assert len(list_recipients(cfg, campaign["id"])) == 0


class TestClickTracking:
    def test_first_click_sets_status(self, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "alice@example.com"},
        ])
        token = results[0]["token"]
        record_recipient_click(cfg, token, device_id="dev1")

        r = get_recipient_by_token(cfg, token)
        assert r["status"] == "clicked"
        assert r["click_count"] == 1
        assert r["first_click_at"] is not None
        assert r["last_click_at"] is not None

    def test_multiple_clicks_increment(self, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "bob@example.com"},
        ])
        token = results[0]["token"]

        record_recipient_click(cfg, token, device_id="dev1")
        record_recipient_click(cfg, token, device_id="dev1")
        record_recipient_click(cfg, token, device_id="dev2")

        r = get_recipient_by_token(cfg, token)
        assert r["click_count"] == 3

    def test_device_ids_accumulate(self, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "carol@example.com"},
        ])
        token = results[0]["token"]

        record_recipient_click(cfg, token, device_id="dev_aaa")
        record_recipient_click(cfg, token, device_id="dev_bbb")
        record_recipient_click(cfg, token, device_id="dev_aaa")

        r = get_recipient_by_token(cfg, token)
        import json
        devices = json.loads(r["device_ids"])
        assert len(devices) == 2
        assert "dev_aaa" in devices
        assert "dev_bbb" in devices

    def test_first_click_at_not_overwritten(self, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "dave@example.com"},
        ])
        token = results[0]["token"]

        record_recipient_click(cfg, token)
        r1 = get_recipient_by_token(cfg, token)
        first = r1["first_click_at"]

        record_recipient_click(cfg, token)
        r2 = get_recipient_by_token(cfg, token)
        assert r2["first_click_at"] == first
        assert r2["last_click_at"] >= first

    def test_click_with_no_device_id(self, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "eve@example.com"},
        ])
        token = results[0]["token"]
        record_recipient_click(cfg, token, device_id=None)

        r = get_recipient_by_token(cfg, token)
        assert r["click_count"] == 1

    def test_invalid_token_click_noop(self, cfg):
        record_recipient_click(cfg, "bogus_token", device_id="dev1")


class TestRecipientStats:
    def test_stats_counts(self, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "a@example.com"},
            {"email": "b@example.com"},
            {"email": "c@example.com"},
        ])
        record_recipient_click(cfg, results[0]["token"])
        record_recipient_click(cfg, results[1]["token"])
        record_recipient_click(cfg, results[1]["token"])

        stats = get_recipient_stats(cfg, campaign["id"])
        assert stats["total"] == 3
        assert stats["clicked"] == 2
        assert stats["pending"] == 1
        assert stats["total_clicks"] == 3
        assert stats["unique_clickers"] == 2
