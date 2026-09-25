"""Tests for device fingerprinting and pre-fetch detection."""

from __future__ import annotations

from bluephishproxy.fingerprint import compute_device_id, detect_prefetch


_REAL_BROWSER_METRICS = {
    "canvasHash": "1a2b3c4d",
    "webglRenderer": "ANGLE (Intel, Intel(R) UHD Graphics 630)",
    "webglVendor": "Google Inc. (Intel)",
    "audioFingerprint": "124.04347657808103",
    "platform": "Win32",
    "timezone": "America/New_York",
    "timezoneOffset": 300,
    "hardwareConcurrency": 8,
    "deviceMemory": 16,
    "colorDepth": 24,
    "screenSize": [1920, 1080],
    "maxTouchPoints": 0,
    "languages": ["en-US", "en"],
    "vendor": "Google Inc.",
    "pdfViewerEnabled": True,
}


class TestDeviceId:
    def test_produces_hex_string(self):
        did = compute_device_id(_REAL_BROWSER_METRICS, "Chrome/120", {})
        assert did is not None
        assert len(did) == 16
        int(did, 16)  # must be valid hex

    def test_stable_across_calls(self):
        a = compute_device_id(_REAL_BROWSER_METRICS, "Chrome/120", {})
        b = compute_device_id(_REAL_BROWSER_METRICS, "Chrome/120", {})
        assert a == b

    def test_different_canvas_different_id(self):
        m2 = {**_REAL_BROWSER_METRICS, "canvasHash": "ffffffff"}
        a = compute_device_id(_REAL_BROWSER_METRICS, "Chrome/120", {})
        b = compute_device_id(m2, "Chrome/120", {})
        assert a != b

    def test_different_screen_different_id(self):
        m2 = {**_REAL_BROWSER_METRICS, "screenSize": [2560, 1440]}
        a = compute_device_id(_REAL_BROWSER_METRICS, "Chrome/120", {})
        b = compute_device_id(m2, "Chrome/120", {})
        assert a != b

    def test_none_metrics_returns_none(self):
        assert compute_device_id(None, "Chrome/120", {}) is None

    def test_empty_metrics_still_produces_id(self):
        did = compute_device_id({}, "Chrome/120", {})
        assert did is not None
        assert len(did) == 16

    def test_sec_ch_platform_contributes(self):
        a = compute_device_id(_REAL_BROWSER_METRICS, "Chrome/120",
                              {"Sec-CH-UA-Platform": '"Windows"'})
        b = compute_device_id(_REAL_BROWSER_METRICS, "Chrome/120",
                              {"Sec-CH-UA-Platform": '"macOS"'})
        assert a != b

    def test_user_agent_not_in_hash(self):
        a = compute_device_id(_REAL_BROWSER_METRICS, "Chrome/120", {})
        b = compute_device_id(_REAL_BROWSER_METRICS, "Chrome/121", {})
        assert a == b


class TestPrefetchDetection:
    def test_outlook_ua(self):
        is_pf, reason = detect_prefetch(
            "Microsoft Office Word/16.0.14326", {}, None, None
        )
        assert is_pf
        assert "microsoft office" in reason

    def test_safelinks_ua(self):
        is_pf, reason = detect_prefetch(
            "Mozilla/5.0 SafeLinks", {}, None, None
        )
        assert is_pf
        assert "safelinks" in reason

    def test_proofpoint_ua(self):
        is_pf, _ = detect_prefetch("Proofpoint URL Defense/1.0", {}, None, None)
        assert is_pf

    def test_mimecast_ua(self):
        is_pf, _ = detect_prefetch("Mimecast URL Scanner", {}, None, None)
        assert is_pf

    def test_slackbot_ua(self):
        is_pf, _ = detect_prefetch("Slackbot-LinkExpanding 1.0", {}, None, None)
        assert is_pf

    def test_exchange_header(self):
        is_pf, reason = detect_prefetch(
            "Mozilla/5.0 Chrome/120",
            {"X-MS-Exchange-Organization-AuthSource": "mail.contoso.com"},
            None, None,
        )
        assert is_pf
        assert "Exchange" in reason

    def test_proofpoint_header(self):
        is_pf, _ = detect_prefetch(
            "Mozilla/5.0",
            {"X-Proofpoint-Spam-Details": "rule=notspam"},
            None, None,
        )
        assert is_pf

    def test_purpose_prefetch_header(self):
        is_pf, _ = detect_prefetch(
            "Mozilla/5.0 Chrome/120",
            {"Purpose": "prefetch"},
            None, None,
        )
        assert is_pf

    def test_sec_purpose_prefetch(self):
        is_pf, _ = detect_prefetch(
            "Mozilla/5.0 Chrome/120",
            {"Sec-Purpose": "prefetch"},
            None, None,
        )
        assert is_pf

    def test_normal_human_not_prefetch(self):
        is_pf, _ = detect_prefetch(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            {"Accept": "text/html", "Accept-Language": "en-US"},
            {"mouseMoves": 12, "clicks": 2},
            3500.0,
        )
        assert not is_pf

    def test_normal_browser_no_js_slow(self):
        is_pf, _ = detect_prefetch(
            "Mozilla/5.0 Chrome/120",
            {},
            None,
            5000.0,
        )
        assert not is_pf

    def test_instant_no_js_is_prefetch(self):
        is_pf, reason = detect_prefetch(
            "Mozilla/5.0 Chrome/120",
            {},
            None,
            50.0,
        )
        assert is_pf
        assert "instant" in reason

    def test_googlebot_prefetch(self):
        is_pf, _ = detect_prefetch("Googlebot/2.1", {}, None, None)
        assert is_pf

    def test_facebookexternalhit(self):
        is_pf, _ = detect_prefetch("facebookexternalhit/1.1", {}, None, None)
        assert is_pf
