"""Shared fixtures for BluePhishProxy tests."""

from __future__ import annotations

import os
import tempfile

import pytest

from bluephishproxy.config import Config
from bluephishproxy.database import init_db


@pytest.fixture()
def tmp_db(tmp_path):
    db_path = str(tmp_path / "test.db")
    os.environ["BPP_DATABASE"] = db_path
    yield db_path
    os.environ.pop("BPP_DATABASE", None)


@pytest.fixture()
def cfg(tmp_db):
    c = Config()
    c.database_path = tmp_db
    init_db(c)
    return c


@pytest.fixture()
def app(cfg):
    from bluephishproxy.app import create_app
    application = create_app(cfg)
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def campaign(cfg):
    from bluephishproxy.database import save_campaign_db
    data = {
        "id": "test-campaign-1",
        "name": "Test Campaign",
        "template": "safelinks",
        "created_at": "2024-01-01T00:00:00Z",
        "active": True,
        "safe_redirect_url": "https://safe.example.com",
        "flagged_redirect_url": "https://blocked.example.com",
        "brand_name": "Microsoft",
        "description": "Test",
        "custom_params": {},
        "redirect_chains": {},
    }
    save_campaign_db(data, cfg)
    return data
