"""Tests for Flask routes — tracking, prefetch filtering, attribution."""

from __future__ import annotations

import json

from bluephishproxy.database import (
    get_recipient_by_token,
    import_recipients,
    list_recipients,
    query_visits,
)


class TestTrackedRoute:
    def test_valid_token_serves_lure(self, client, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "alice@example.com"},
        ])
        token = results[0]["token"]
        resp = client.get(f"/t/{token}")
        assert resp.status_code == 200
        assert b"Microsoft" in resp.data

    def test_invalid_token_404(self, client):
        resp = client.get("/t/nonexistent")
        assert resp.status_code == 404

    def test_tracked_visit_records_token(self, client, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "bob@example.com"},
        ])
        token = results[0]["token"]
        client.get(f"/t/{token}")

        visits = query_visits(cfg, campaign_id=campaign["id"])
        assert len(visits) >= 1
        assert visits[0]["tracking_token"] == token

    def test_tracked_visit_records_recipient_id(self, client, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "carol@example.com"},
        ])
        token = results[0]["token"]
        recipient = get_recipient_by_token(cfg, token)
        client.get(f"/t/{token}")

        visits = query_visits(cfg, campaign_id=campaign["id"])
        assert visits[0]["recipient_id"] == recipient["id"]

    def test_inactive_campaign_returns_404(self, client, cfg, campaign):
        from bluephishproxy.database import save_campaign_db
        campaign["active"] = False
        save_campaign_db(campaign, cfg)

        results = import_recipients(cfg, campaign["id"], [
            {"email": "dave@example.com"},
        ])
        resp = client.get(f"/t/{results[0]['token']}")
        assert resp.status_code == 404

    def test_subpath_still_works(self, client, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "eve@example.com"},
        ])
        token = results[0]["token"]
        resp = client.get(f"/t/{token}/some/path")
        assert resp.status_code == 200


class TestPrefetchInRoute:
    def test_prefetch_ua_visit_marked(self, client, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "frank@example.com"},
        ])
        token = results[0]["token"]
        client.get(
            f"/t/{token}",
            headers={"User-Agent": "Microsoft Office Word/16.0"},
        )

        visits = query_visits(cfg, campaign_id=campaign["id"])
        assert visits[0]["is_prefetch"] == 1
        assert "microsoft office" in visits[0]["prefetch_reason"]

    def test_prefetch_does_not_count_as_click(self, client, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "grace@example.com"},
        ])
        token = results[0]["token"]
        client.get(
            f"/t/{token}",
            headers={"User-Agent": "Microsoft Office Word/16.0"},
        )

        r = get_recipient_by_token(cfg, token)
        assert r["status"] == "pending"
        assert r["click_count"] == 0


class TestRecipientAPI:
    def test_import_via_api(self, client, cfg, campaign):
        resp = client.post(
            "/api/operator/recipients",
            json={
                "campaign_id": campaign["id"],
                "targets": [
                    {"email": "api1@example.com", "name": "API User 1"},
                    {"email": "api2@example.com"},
                ],
            },
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["imported"] == 2
        assert all("tracking_url" in r for r in data["recipients"])
        assert all("/t/" in r["tracking_url"] for r in data["recipients"])

    def test_import_requires_campaign_id(self, client):
        resp = client.post(
            "/api/operator/recipients",
            json={"targets": [{"email": "x@x.com"}]},
        )
        assert resp.status_code == 400

    def test_import_requires_targets(self, client, cfg, campaign):
        resp = client.post(
            "/api/operator/recipients",
            json={"campaign_id": campaign["id"]},
        )
        assert resp.status_code == 400

    def test_import_requires_email_field(self, client, cfg, campaign):
        resp = client.post(
            "/api/operator/recipients",
            json={
                "campaign_id": campaign["id"],
                "targets": [{"name": "No Email"}],
            },
        )
        assert resp.status_code == 400

    def test_list_via_api(self, client, cfg, campaign):
        import_recipients(cfg, campaign["id"], [
            {"email": "list1@example.com"},
            {"email": "list2@example.com"},
        ])
        resp = client.get(f"/api/operator/recipients?campaign_id={campaign['id']}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 2

    def test_stats_via_api(self, client, cfg, campaign):
        results = import_recipients(cfg, campaign["id"], [
            {"email": "s1@example.com"},
            {"email": "s2@example.com"},
        ])
        from bluephishproxy.database import record_recipient_click
        record_recipient_click(cfg, results[0]["token"])

        resp = client.get(f"/api/operator/recipients/stats?campaign_id={campaign['id']}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 2
        assert data["clicked"] == 1

    def test_delete_via_api(self, client, cfg, campaign):
        import_recipients(cfg, campaign["id"], [
            {"email": "del@example.com"},
        ])
        recipients = list_recipients(cfg, campaign["id"])
        rid = recipients[0]["id"]

        resp = client.delete(f"/api/operator/recipients/{rid}")
        assert resp.status_code == 200
        assert len(list_recipients(cfg, campaign["id"])) == 0


class TestCampaignRoute:
    def test_campaign_route_no_tracking(self, client, cfg, campaign):
        resp = client.get(f"/c/{campaign['id']}/")
        assert resp.status_code == 200
        visits = query_visits(cfg)
        assert visits[0]["tracking_token"] is None

    def test_catchall_route(self, client, cfg):
        resp = client.get("/some/random/path")
        assert resp.status_code == 200


class TestHealthCheck:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"
