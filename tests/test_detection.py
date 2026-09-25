"""Tests for detection engine — scoring, signals, visit record building."""

from __future__ import annotations

from bluephishproxy.detection import build_visit_record, evaluate


class TestEvaluate:
    def test_clean_browser(self, cfg):
        v = evaluate(
            ip="10.0.0.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            headers={"Accept-Language": "en-US", "Accept-Encoding": "gzip"},
            js_metrics={"mouseMoves": 15, "clicks": 3, "webdriver": False,
                        "automationAPIs": False, "pluginCount": 3,
                        "languageCount": 2, "canvasBlocked": False,
                        "audioBlocked": False, "windowOuter": [1920, 1080],
                        "screenSize": [1920, 1080], "windowSize": [1200, 800],
                        "colorDepth": 24, "touchSupport": False,
                        "hasTouchEvents": False},
            elapsed_ms=4500.0,
            cfg=cfg,
        )
        assert v.classification == "clean"
        assert v.score < cfg.suspicious_threshold

    def test_headless_chrome(self, cfg):
        v = evaluate(
            ip="10.0.0.1",
            user_agent="Mozilla/5.0 HeadlessChrome/120",
            headers={},
            js_metrics={"webdriver": True, "mouseMoves": 0},
            elapsed_ms=100.0,
            cfg=cfg,
        )
        assert v.classification == "bot"
        assert v.score >= cfg.bot_threshold

    def test_missing_ua_suspicious(self, cfg):
        v = evaluate(
            ip="10.0.0.1",
            user_agent="",
            headers={},
            js_metrics=None,
            elapsed_ms=None,
            cfg=cfg,
        )
        assert v.score >= cfg.suspicious_threshold

    def test_curl_ua(self, cfg):
        v = evaluate(
            ip="10.0.0.1",
            user_agent="curl/7.88.1",
            headers={},
            js_metrics=None,
            elapsed_ms=None,
            cfg=cfg,
        )
        assert v.classification == "bot"


class TestBuildVisitRecord:
    def test_record_has_device_id_with_js(self, cfg):
        record = build_visit_record(
            ip="10.0.0.1",
            user_agent="Mozilla/5.0 Chrome/120",
            headers={},
            cookies={},
            path="/t/abc",
            method="GET",
            args={},
            referrer=None,
            session_id="sess1",
            js_metrics={"canvasHash": "abc", "screenSize": [1920, 1080]},
            elapsed_ms=3000.0,
            cfg=cfg,
        )
        assert "device_id" in record
        assert len(record["device_id"]) == 16

    def test_record_no_device_id_without_js(self, cfg):
        record = build_visit_record(
            ip="10.0.0.1",
            user_agent="Mozilla/5.0",
            headers={},
            cookies={},
            path="/",
            method="GET",
            args={},
            referrer=None,
            session_id="sess2",
            js_metrics=None,
            elapsed_ms=None,
            cfg=cfg,
        )
        assert record.get("device_id") is None

    def test_prefetch_detected_in_record(self, cfg):
        record = build_visit_record(
            ip="10.0.0.1",
            user_agent="Microsoft Office Word/16.0",
            headers={},
            cookies={},
            path="/t/xyz",
            method="GET",
            args={},
            referrer=None,
            session_id="sess3",
            js_metrics=None,
            elapsed_ms=50.0,
            cfg=cfg,
        )
        assert record.get("is_prefetch") is True
        assert "microsoft office" in record.get("prefetch_reason", "")

    def test_normal_visit_not_prefetch(self, cfg):
        record = build_visit_record(
            ip="10.0.0.1",
            user_agent="Mozilla/5.0 Chrome/120",
            headers={"Accept-Language": "en-US"},
            cookies={},
            path="/t/abc",
            method="GET",
            args={},
            referrer=None,
            session_id="sess4",
            js_metrics={"mouseMoves": 10, "clicks": 2},
            elapsed_ms=4000.0,
            cfg=cfg,
        )
        assert not record.get("is_prefetch")
